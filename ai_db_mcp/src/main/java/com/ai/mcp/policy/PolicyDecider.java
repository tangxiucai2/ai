package com.ai.mcp.policy;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * HOST 类访问控制裁决
 * <p>
 * 结果是三值 + 一个"谁来确认": ALLOW / DENY / CONFIRM(本人确认) / APPROVAL(管理员审批).
 * <p>
 * 两条容易记反的语义:
 * <ul>
 *   <li>命中不是终局。黑名单命中后仍要看 approvalMode, 黑名单 + 本人确认通过 = <b>放行</b>。</li>
 *   <li>确认通过不再回头查白名单 —— 人都点了确认还说"不在白名单里"是自相矛盾。</li>
 * </ul>
 */
@Component
public class PolicyDecider {

    /** 复合语法与重定向: 一条命令里出现即不许白名单自动放行 */
    private static final Pattern COMPOUND = Pattern.compile("[;&|`$()<>\\r\\n]");

    /** 命令名尾部残留的 shell 元字符: "ls;" 也要能对上 ls 策略 */
    private static final Pattern TRAILING_META = Pattern.compile("[;&|`$()<>]+$");

    private static final String MODE_NONE = "NONE";

    private static final String MODE_CONFIRM = "CONFIRM";

    private static final String MODE_APPROVAL = "APPROVAL";

    /** 白名单侧的严格度次序: 越靠后越严 (黑名单侧见 {@link #denyMode}: NONE 是最严的一档) */
    private static final List<String> MODES = List.of(MODE_NONE, MODE_CONFIRM, MODE_APPROVAL);

    public enum Kind {
        /** 通过 */
        ALLOW,
        /** 拒绝 */
        DENY,
        /** 需发起人本人二次确认 */
        CONFIRM,
        /** 需管理员审批 (本期不产出放行, 一律拒) */
        APPROVAL
    }

    /**
     * 判定的来源环节: 审计要靠它把「策略拒绝」与「人工拒绝」分开 ——
     * 两者在状态列都是「已拒绝」, 混在一起会让访问控制审计分不清"是策略拦的还是人拦的"
     */
    public enum Source {
        /** 策略判定 (黑白名单 / 限流 / 白名单未命中 / 规则无效) */
        POLICY,
        /** 人工确认环节 (本人拒绝 / 取消 / 超时 / 客户端不支持 / 确认后授权复检不过) */
        CONFIRM,
        /** 鉴权环节 (拿不到调用身份这类, 压根没走到策略) */
        AUTH
    }

    /**
     * @param policyLabel   命中的策略 (供弹窗与审计展示); 未命中任何策略时为 null
     * @param confirmWaited 这次判定在人工确认上阻塞过 (最长 CONFIRM_TIMEOUT_SEC 秒):
     *                      等待期间凭据可能已被管理员撤销/过期, 调用方用句柄前必须重校验授权
     * @param source        判定来源, 决定审计里归到哪一类拒绝
     */
    public record Decision(Kind kind, String reason, String policyLabel, boolean confirmWaited, Source source) {

        /** 策略判定 (默认来源) */
        static Decision of(Kind k, String reason, String policyLabel) {
            return new Decision(k, reason, policyLabel, false, Source.POLICY);
        }

        /** 鉴权环节的判定: 没走到策略, 审计归「鉴权」 */
        static Decision auth(Kind k, String reason) {
            return new Decision(k, reason, null, false, Source.AUTH);
        }

        /** 人工确认环节的判定 (放行与拒绝都算): 审计归「人工」 */
        static Decision confirm(Kind k, String reason, String policyLabel) {
            return new Decision(k, reason, policyLabel, false, Source.CONFIRM);
        }

        /** 标记这次判定经过了人工确认等待 */
        Decision waited() {
            return new Decision(kind, reason, policyLabel, true, source);
        }
    }

    /**
     * 命令解析结果
     *
     * @param segmentTokens 复合命令按分隔符拆段后, 每段里的**全部**词 (非复合命令只有一个元素, 等于 name)。
     *                      拒绝侧匹配要扫描这个而不是只看 name —— 见 {@link #governs}
     */
    record Parsed(String name, String raw, boolean compound, boolean explicitPath, List<String> segmentTokens) {
    }

    private final PolicyStore store;
    private final PolicyRateLimiter limiter = new PolicyRateLimiter();

    public PolicyDecider(PolicyStore store) {
        this.store = store;
    }

    /**
     * @param agentId   实际智能体 id (来自凭据解析, 不是客户端自称)
     * @param hostType  目标资源主类型 (HOST 类恒 SSH)
     * @param hostId    目标资源 id; null 表示拿不到 —— 拿不到就不许扩大范围, 直接拒
     * @param command   原始命令串
     */
    public Decision decide(long agentId, String hostType, Long hostId, String command) {
        if (store.unavailable()) {
            return Decision.of(Kind.DENY, "访问控制策略源不可用, 已暂停命令执行", null);
        }
        if (hostId == null) {
            return Decision.of(Kind.DENY, "无法确定目标资源, 不能按策略放行", null);
        }
        List<PolicyStore.Policy> policies = store.snapshot().policies();
        List<PolicyStore.Policy> applicable = applicable(policies, agentId, hostType, hostId);
        // 限流单独一套: 它不参与黑白名单匹配, 但同样要按智能体/资源定范围
        List<PolicyStore.Policy> rates = ratePolicies(policies, agentId, hostType, hostId);
        // 无效优先: 规则读不出来的策略不能当"没有这条策略"跳过 —— 丢掉的可能是 deny 项,
        // 后面再有一条白名单命中就变成放行了 (设计文档: 无效规则按拒绝处理)
        for (PolicyStore.Policy p : applicable) {
            if (p.rulesInvalid()) {
                return Decision.of(Kind.DENY, "命中策略规则无效, 已按拒绝处理", label(List.of(p)));
            }
        }
        // 限流快速检查放在弹窗之前: 超限直接拒, 不去打扰用户点确认 (确认最长要等 120 秒)
        for (PolicyStore.Policy p : rates) {
            if (limiter.exceeded(p.id(), p.limit(), p.windowSeconds())) {
                return Decision.of(Kind.DENY,
                        "超出频率限制 (" + p.limit() + " 次 / " + p.windowSeconds() + " 秒), 已拒绝执行",
                        label(List.of(p)));
            }
        }
        if (applicable.isEmpty()) {
            // 该智能体没有黑白名单 (压根没策略, 或只有限流策略) → 维持接入前的现状放行.
            // 只有限流的智能体绝不能落到"未命中任何白名单": 那等于配了限流就把所有命令封死
            return Decision.of(Kind.ALLOW, null, null);
        }
        Parsed parsed = parse(command);
        List<PolicyStore.Policy> gov;
        String base;
        String why;

        List<PolicyStore.Policy> deny = matchDeny(applicable, parsed);
        List<PolicyStore.Policy> allow = matchAllow(applicable, parsed);
        if (!deny.isEmpty()) {
            gov = deny;
            base = "DENY";
            why = "命中黑名单";
        } else {
            if (allow.isEmpty()) {
                // 严格模式: 该智能体有策略但这条命令未被明确允许
                return Decision.of(Kind.DENY, "未命中任何白名单, 该智能体已配置访问控制策略", label(applicable));
            }
            gov = allow;
            boolean clean = !parsed.compound() && !parsed.explicitPath();
            base = clean ? "ALLOW" : "DENY";
            why = clean ? "命中白名单" : parsed.compound() ? "复合命令不允许白名单自动放行" : "显式路径命令不允许白名单自动放行";
        }

        // 拒判基调下取档位的次序**与白名单那边相反**: 黑名单的 NONE 是"无条件拒绝", 比 CONFIRM 严;
        // 照白名单的 NONE < CONFIRM 取最大, "一条 NONE + 一条 CONFIRM"会变成可确认放行.
        // 所以只有"全部命中黑名单都是 CONFIRM"才允许本人确认
        String mode = deny.isEmpty() ? strictestMode(gov) : denyMode(gov);
        String policyLabel = label(gov);
        // 另有命中的白名单时, 它只能再加一道严的: 只有 APPROVAL 允许覆盖, 且不覆盖"无条件拒绝".
        // 白名单的 CONFIRM 不能把黑名单的直接拒救成可确认, 白名单的 NONE (直接放行) 更不能
        List<PolicyStore.Policy> matched = new ArrayList<>(deny);
        matched.addAll(allow);
        if (!MODE_NONE.equals(mode) && anyApproval(matched)) {
            mode = MODE_APPROVAL;
            // 档位是别条策略抬上来的, 标签得跟着走 —— 否则审计里指的策略不是要求审批的那条
            policyLabel = label(matched);
        }
        switch (mode) {
            case "APPROVAL":
                // 本期不产出放行: 协议级弹窗是同步阻塞的, 撑不起 24h 异步审批
                return Decision.of(Kind.APPROVAL, "该策略需管理员审批, 管理员审批暂未生效", policyLabel);
            case "CONFIRM":
                return Decision.of(Kind.CONFIRM, why, policyLabel);
            default:
                return "ALLOW".equals(base)
                        ? Decision.of(Kind.ALLOW, why, policyLabel)
                        : Decision.of(Kind.DENY, why, policyLabel);
        }
    }

    /**
     * 黑白名单适用集: 智能体匹配 (0=全部), 且 (全局策略且类型匹配) 或 (指定该资源).
     * 全局与具体同时参与, 具体不覆盖全局
     * <p>
     * 有效的限流类不进这个集合 —— 它既不判定命令, 也绝不能算「该智能体有策略」:
     * 算进去的话, 只配了限流、没配黑白名单的智能体, 每条命令都会落进严格模式被拒.
     * <b>但规则无效的限流要留下</b> —— 无效规则按拒绝处理 (结论 17), 排除了就成了静默忽略
     */
    private static List<PolicyStore.Policy> applicable(List<PolicyStore.Policy> all, long agentId, String hostType, long hostId) {
        List<PolicyStore.Policy> out = new ArrayList<>();
        for (PolicyStore.Policy p : all) {
            if (!inScope(p, agentId, hostType, hostId)) {
                continue;
            }
            if (PolicyStore.TYPE_RATE_LIMIT.equals(p.type()) && !p.rulesInvalid()) {
                continue;
            }
            out.add(p);
        }
        return out;
    }

    /** 有效限流适用集: 逐条按其自己的窗口记账, 命中任一条超限即拒 */
    private static List<PolicyStore.Policy> ratePolicies(List<PolicyStore.Policy> all, long agentId, String hostType, long hostId) {
        List<PolicyStore.Policy> out = new ArrayList<>();
        for (PolicyStore.Policy p : all) {
            if (PolicyStore.TYPE_RATE_LIMIT.equals(p.type()) && !p.rulesInvalid() && inScope(p, agentId, hostType, hostId)) {
                out.add(p);
            }
        }
        return out;
    }

    /** 策略是否管这次调用: 智能体匹配 (0=全部), 且 (全局且类型匹配) 或 (指定该资源) */
    private static boolean inScope(PolicyStore.Policy p, long agentId, String hostType, long hostId) {
        if (p.agentId() != 0 && p.agentId() != agentId) {
            return false;
        }
        boolean global = p.hostId() == 0 && p.hostType() != null && p.hostType().equals(hostType);
        return global || p.hostId() == hostId;
    }

    /**
     * 放行执行时记账: 给这次调用命中的限流策略各 +1
     * <p>
     * 由调用方在**判定为放行之后**调, 只对真正执行的调用计数 (结论 16): 被拒的、弹窗没过的、超限的
     * 都不占配额 —— 否则用被拒命令就能把配额刷满. 授权复检失败那一步在这之后才发生, 那种极少数
     * 情况会多计一次, 是刻意接受的小偏差 (反向"预留再回退"会引入配额泄漏, 更糟)
     */
    public void recordRate(long agentId, String hostType, Long hostId) {
        if (hostId == null) {
            return;
        }
        for (PolicyStore.Policy p : ratePolicies(store.snapshot().policies(), agentId, hostType, hostId)) {
            limiter.record(p.id(), p.windowSeconds());
        }
    }

    /**
     * 命令解析: 命令名取首个 token (去掉尾随 shell 元字符, 让 "ls;" 也能对上 ls),
     * 复合语法与显式路径各记一个标志
     */
    static Parsed parse(String command) {
        String raw = command == null ? "" : command.trim();
        int sp = 0;
        while (sp < raw.length() && !Character.isWhitespace(raw.charAt(sp))) {
            sp++;
        }
        String token = raw.substring(0, sp);
        String name = TRAILING_META.matcher(token).replaceFirst("");
        return new Parsed(name, raw, COMPOUND.matcher(raw).find(), token.indexOf('/') >= 0, segmentTokens(raw));
    }

    /**
     * 按复合分隔符拆段, 收集**全部**段里的**全部**词 (不止首段、不止段首那一个词)
     * <p>
     * 拒绝侧必须看到每一段: "echo ok; rm -rf /" 若只比第一段(echo), 排在后面的 rm 永远查不到黑名单,
     * NONE 档"无条件拒绝、不给确认机会"的承诺就被绕过了。段内也不能只取第一个词: "sudo rm -rf /"
     * 这种在真正命令前面加一层包装词(sudo/command/exec/env/nohup/...)的写法根本不需要任何分隔符,
     * 光看段首会一直停在包装词上, 永远比不到 rm —— 这类包装词多到没法穷举, 干脆把整条命令拆出的
     * 每个词都拿去比对 (EXACT 仍是"某个词恰好等于策略值"的精确匹配, 不像 KEYWORD 那样命中子串,
     * 不会把 "germ" 误判成含 "rm")。非复合命令走的是同一套逻辑, 只是天然只有一段。
     * 白名单侧不受影响, 仍然只认首词 —— 复合命令本来就不许白名单自动放行, 不需要看更多段/词
     */
    private static List<String> segmentTokens(String raw) {
        List<String> tokens = new ArrayList<>();
        for (String seg : raw.split("[;&|`$()<>\\r\\n]+")) {
            for (String word : seg.trim().split("\\s+")) {
                String t = TRAILING_META.matcher(word).replaceFirst("");
                if (!t.isEmpty()) {
                    tokens.add(t);
                    // 同一个词再加一份去掉引号/反斜杠转义的版本: "env -- 'r'm" 这种拼接手法
                    // 不产生任何分隔符, 原样比对永远凑不出 "rm" —— 去引号后的还原值一并纳入比对,
                    // 只增不减 (拒绝侧宽匹配, 多命中不会误伤白名单那一侧)
                    String unquoted = stripQuotes(t);
                    if (!unquoted.isEmpty() && !unquoted.equals(t)) {
                        tokens.add(unquoted);
                    }
                }
            }
        }
        return tokens;
    }

    /** 去掉未转义的单/双引号与反斜杠转义, 还原 shell 会拼出的实际词 (不追求完整 shell 语法) */
    private static String stripQuotes(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\'' || c == '"') {
                continue;
            }
            if (c == '\\' && i + 1 < s.length()) {
                sb.append(s.charAt(++i));
                continue;
            }
            sb.append(c);
        }
        return sb.toString();
    }

    /**
     * 拒绝侧宽匹配: 显式路径退回 basename 比 (否则 /bin/rm 就绕过了 rm 的黑名单),
     * KEYWORD/REGEX 作用于原始串
     */
    static boolean hitDeny(PolicyStore.Op op, Parsed p) {
        return governs(op, p, true);
    }

    /** 放行侧严匹配: 显式路径不参与 (智能体送的路径一律不认) */
    static boolean hitAllow(PolicyStore.Op op, Parsed p) {
        if (p.explicitPath()) {
            return false;
        }
        return governs(op, p, false);
    }

    /**
     * @param withBasename 是否允许用 basename 兜底匹配 (拒绝侧才允许)
     */
    private static boolean governs(PolicyStore.Op op, Parsed p, boolean withBasename) {
        String value = op.value();
        if (value == null || value.isEmpty()) {
            return false;
        }
        switch (op.matchType()) {
            case "EXACT":
                if (!withBasename) {
                    return value.equals(p.name());
                }
                // 拒绝侧扫描每段里的每个词 (含 basename 兜底) —— 见 segmentTokens() 的说明
                for (String seg : p.segmentTokens()) {
                    if (value.equals(seg) || value.equals(basename(seg))) {
                        return true;
                    }
                }
                return false;
            case "KEYWORD":
                return p.raw().contains(value);
            case "REGEX":
                Pattern pattern = compile(value);
                return pattern != null && pattern.matcher(p.raw()).find();
            default:
                return false;
        }
    }

    private static List<PolicyStore.Policy> matchDeny(List<PolicyStore.Policy> policies, Parsed parsed) {
        List<PolicyStore.Policy> out = new ArrayList<>();
        for (PolicyStore.Policy p : policies) {
            if (PolicyStore.TYPE_BLACKLIST.equals(p.type()) && anyHit(p, parsed, true)) {
                out.add(p);
            }
        }
        return out;
    }

    private static List<PolicyStore.Policy> matchAllow(List<PolicyStore.Policy> policies, Parsed parsed) {
        List<PolicyStore.Policy> out = new ArrayList<>();
        for (PolicyStore.Policy p : policies) {
            if (PolicyStore.TYPE_WHITELIST.equals(p.type()) && anyHit(p, parsed, false)) {
                out.add(p);
            }
        }
        return out;
    }

    private static boolean anyHit(PolicyStore.Policy policy, Parsed parsed, boolean denySide) {
        for (PolicyStore.Op op : policy.ops()) {
            if (denySide ? hitDeny(op, parsed) : hitAllow(op, parsed)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 拒判基调下的档位: 只要有一条黑名单是 NONE (无条件拒绝) 或 APPROVAL, 就不允许本人确认;
     * 全部是 CONFIRM 时才落到 CONFIRM
     * <p>
     * 不能复用 {@link #strictestMode}: 那是白名单的次序 (NONE 最松)。NONE 只在黑名单一侧表示"无条件"
     */
    private static String denyMode(List<PolicyStore.Policy> policies) {
        String out = MODE_CONFIRM;
        for (PolicyStore.Policy p : policies) {
            String m = p.approvalMode() == null ? MODE_NONE : p.approvalMode();
            if (MODE_NONE.equals(m)) {
                return MODE_NONE;
            }
            if (MODE_APPROVAL.equals(m)) {
                out = MODE_APPROVAL;
            }
        }
        return out;
    }

    private static boolean anyApproval(List<PolicyStore.Policy> policies) {
        for (PolicyStore.Policy p : policies) {
            if (MODE_APPROVAL.equals(p.approvalMode())) {
                return true;
            }
        }
        return false;
    }

    /** 多策略同时命中取更严格的一档 (白名单侧次序: APPROVAL > CONFIRM > NONE) */
    private static String strictestMode(List<PolicyStore.Policy> policies) {
        int max = 0;
        for (PolicyStore.Policy p : policies) {
            int i = MODES.indexOf(p.approvalMode() == null ? "NONE" : p.approvalMode());
            if (i > max) {
                max = i;
            }
        }
        return MODES.get(max);
    }

    /** 命中策略的可读标签, 进弹窗与审计 */
    static String label(List<PolicyStore.Policy> policies) {
        StringBuilder sb = new StringBuilder();
        for (PolicyStore.Policy p : policies) {
            if (sb.length() > 0) {
                sb.append(',');
            }
            sb.append('#').append(p.id()).append(' ').append(p.type());
        }
        return sb.toString();
    }

    private static String basename(String name) {
        int slash = name.lastIndexOf('/');
        return slash < 0 ? name : name.substring(slash + 1);
    }

    /** 策略里的正则由控制台按值域校验过; 仍然兜一层, 语法错不外抛 */
    private static Pattern compile(String regex) {
        try {
            return Pattern.compile(regex);
        } catch (PatternSyntaxException e) {
            return null;
        }
    }
}
