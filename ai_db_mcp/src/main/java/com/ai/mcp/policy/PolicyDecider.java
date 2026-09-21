package com.ai.mcp.policy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.ResolverStyle;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Pattern;

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

    private static final Logger log = LoggerFactory.getLogger(PolicyDecider.class);

    /** 时间段判定固定用北京时间, 不依赖网关 JVM 的默认时区 (可能跑在 UTC 容器里) */
    private static final ZoneId BUSINESS_ZONE = ZoneId.of("Asia/Shanghai");

    private static final DateTimeFormatter TIME_FORMATTER =
            DateTimeFormatter.ofPattern("HH:mm:ss").withResolverStyle(ResolverStyle.STRICT);
    private static final DateTimeFormatter DATE_TIME_FORMATTER =
            DateTimeFormatter.ofPattern("uuuu-MM-dd HH:mm:ss").withResolverStyle(ResolverStyle.STRICT);

    /** 复合语法与重定向: 一条命令里出现即不许白名单自动放行 */
    private static final Pattern COMPOUND = Pattern.compile("[;&|`$()<>\\r\\n]");

    /** 命令名尾部残留的 shell 元字符: "ls;" 也要能对上 ls 策略 */
    private static final Pattern TRAILING_META = Pattern.compile("[;&|`$()<>]+$");

    private static final String MODE_NONE = "NONE";

    private static final String MODE_CONFIRM = "CONFIRM";

    private static final String MODE_APPROVAL = "APPROVAL";

    /** 二次确认 + 风险审批都要 (单列四值, 不额外加布尔列): 先确认后审批, 任一环节拒绝即终止 */
    private static final String MODE_BOTH = "BOTH";

    /** 白名单侧的严格度次序: 越靠后越严 (黑名单侧见 {@link #denyMode}: NONE 是最严的一档) */
    private static final List<String> MODES = List.of(MODE_NONE, MODE_CONFIRM, MODE_APPROVAL, MODE_BOTH);

    public enum Kind {
        /** 通过 */
        ALLOW,
        /** 拒绝 */
        DENY,
        /** 需发起人本人二次确认 */
        CONFIRM,
        /** 需管理员审批: decide() 判定为这一档时, PolicyGate 会走 /gate 闸门 (第二部分) */
        APPROVAL,
        /** 二次确认 + 风险审批都要: PolicyGate 先 confirm() 再 approval(), 任一环节拒绝即终止 */
        BOTH
    }

    /**
     * 判定的来源环节: 审计要靠它把「策略拒绝」「人工拒绝」「审批拦截」分开 ——
     * 这几类在状态列都是「已拒绝」, 混在一起会让访问控制审计分不清是谁拦的
     */
    public enum Source {
        /** 策略判定 (黑白名单 / 限流 / 白名单未命中 / 规则无效) */
        POLICY,
        /** 人工确认环节 (本人拒绝 / 取消 / 超时 / 客户端不支持 / 确认后授权复检不过) */
        CONFIRM,
        /** 审批闸门环节 (第二部分: 已提交/审批中/已被拒绝/审批服务不可用/加锁繁忙, 或最终放行) */
        APPROVAL,
        /** 鉴权环节 (拿不到调用身份这类, 压根没走到策略) */
        AUTH
    }

    /**
     * @param policyLabel     命中的策略 (供弹窗与审计展示); 未命中任何策略时为 null
     * @param confirmWaited   这次判定在人工确认/审批闸门上阻塞过 (最长按控制台下发的确认超时, 或 /gate 的 HTTP 往返):
     *                        等待期间凭据可能已被管理员撤销/过期, 调用方用句柄前必须重校验授权
     * @param source          判定来源, 决定审计里归到哪一类拒绝
     * @param policyRevision  仅 decide() 判定为 APPROVAL 或 BOTH 时有值: 这次裁决实际命中的策略内容摘要 (设计文档 §2.1a),
     *                        PolicyGate.approval() 用它组装 /gate 请求体, 与消费后 fresh decide 的结果比对
     * @param approvalNo      仅审批闸门 PENDING/REJECTED 结果有值: 结构化返回给智能体, 引导原样重试 (设计文档结论 9)
     * @param approvalStatus  同上, 取值 PENDING/REJECTED
     * @param policyType      仅 decide() 判定为 APPROVAL 或 BOTH 时有值: 命中策略类型的中文标签 (操作黑名单/操作白名单,
     *                        可能逗号并列多个), 审批单标题展示用, 与 policyLabel (策略名称+规则摘要) 是两码事
     */
    public record Decision(Kind kind, String reason, String policyLabel, boolean confirmWaited, Source source,
                           String policyRevision, String approvalNo, String approvalStatus, String policyType) {

        /** 策略判定 (默认来源) */
        static Decision of(Kind k, String reason, String policyLabel) {
            return new Decision(k, reason, policyLabel, false, Source.POLICY, null, null, null, null);
        }

        /** 鉴权环节的判定: 没走到策略, 审计归「鉴权」 */
        static Decision auth(Kind k, String reason) {
            return new Decision(k, reason, null, false, Source.AUTH, null, null, null, null);
        }

        /** 人工确认环节的判定 (放行与拒绝都算): 审计归「人工」 */
        static Decision confirm(Kind k, String reason, String policyLabel) {
            return new Decision(k, reason, policyLabel, false, Source.CONFIRM, null, null, null, null);
        }

        /** 审批闸门环节的判定 (建单/不可达/加锁繁忙/最终放行/fresh-decide 拒绝都算): 审计归「审批」, 第二部分新增 */
        static Decision approval(Kind k, String reason, String policyLabel) {
            return new Decision(k, reason, policyLabel, false, Source.APPROVAL, null, null, null, null);
        }

        /** 审批闸门 PENDING/REJECTED 结果专用: 带上单号/状态供调用方结构化返回给智能体 (设计文档结论 9) */
        static Decision approval(Kind k, String reason, String policyLabel, String approvalNo, String approvalStatus) {
            return new Decision(k, reason, policyLabel, false, Source.APPROVAL, null, approvalNo, approvalStatus, null);
        }

        /** 标记这次判定经过了人工确认/审批闸门等待 */
        Decision waited() {
            return new Decision(kind, reason, policyLabel, true, source, policyRevision, approvalNo, approvalStatus, policyType);
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
        return decide(agentId, hostType, hostId, command, ZonedDateTime.now(BUSINESS_ZONE));
    }

    /** 包级重载: 测试可传入固定时刻, 稳定覆盖时间段跨边界行为 */
    Decision decide(long agentId, String hostType, Long hostId, String command, ZonedDateTime now) {
        if (store.unavailable()) {
            return Decision.of(Kind.DENY, "访问控制策略源不可用, 已暂停命令执行", null);
        }
        if (hostId == null) {
            return Decision.of(Kind.DENY, "无法确定目标资源, 不能按策略放行", null);
        }
        List<PolicyStore.Policy> policies = store.snapshot().policies();
        List<PolicyStore.Policy> applicable = applicable(policies, agentId, hostType, hostId, now);
        // 限流单独一套: 它不参与黑白名单匹配, 但同样要按智能体/资源定范围.
        // 优先级收敛: 只有最高优先级那几条限流器参与超限判定 (recordRate 用同一个函数, 否则会记了不判/判了不记)
        List<PolicyStore.Policy> rates = topPriority(ratePolicies(policies, agentId, hostType, hostId, now));
        // 无效优先: 规则读不出来的策略不能当"没有这条策略"跳过 —— 丢掉的可能是 deny 项,
        // 后面再有一条白名单命中就变成放行了 (设计文档: 无效规则按拒绝处理)
        for (PolicyStore.Policy p : applicable) {
            if (p.rulesInvalid()) {
                return Decision.of(Kind.DENY, "命中策略规则无效, 已按拒绝处理", label(List.of(p)));
            }
        }
        // 限流快速检查放在弹窗之前: 超限直接拒, 不去打扰用户点确认 (确认最长要等控制台下发的确认超时, 至多 300 秒)
        for (PolicyStore.Policy p : rates) {
            if (limiter.exceeded(p.id(), p.limit(), p.windowSeconds())) {
                // 具体配额不进对外文案: 告诉调用方"N 次 / M 秒"等于把限流参数交给它去卡点重试,
                // 审计要的那份在 label() 里 (rulesSummary 本身就是"N 次 / M 秒")
                return Decision.of(Kind.DENY, "超出频率限制, 已拒绝执行", label(List.of(p)));
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

        // 黑/白名单各自按优先级收敛后再往下走: 以下的 deny-wins、抬档、policyRevision 原样吃收敛后的集合
        List<PolicyStore.Policy> deny = topPriority(matchDeny(applicable, parsed));
        List<PolicyStore.Policy> allow = topPriority(matchAllow(applicable, parsed));
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
        if (!MODE_NONE.equals(mode) && requiresApproval(matched)) {
            // 升到 APPROVAL 还是 BOTH 取决于抬档的是哪条: 命中集合里只要有一条 BOTH 就不能把"还需要
            // 确认"这个要求吞掉, 必须升到 BOTH; 都是 APPROVAL 才升到 APPROVAL
            mode = matched.stream().anyMatch(p -> MODE_BOTH.equals(p.approvalMode())) ? MODE_BOTH : MODE_APPROVAL;
            // 档位是别条策略抬上来的, 标签得跟着走 —— 否则审计里指的策略不是要求审批的那条
            policyLabel = label(matched);
        }
        switch (mode) {
            case "APPROVAL":
                // 第二部分: 生效了, 不再是"暂未生效"——PolicyGate 收到这一档会走 /gate 闸门。
                // policyRevision 只摘要这次裁决实际命中的 matched (deny∪allow), 不是全部启用策略 (设计文档 §2.1a)
                return new Decision(Kind.APPROVAL, "该策略需管理员审批", policyLabel, false, Source.POLICY,
                        policyRevision(matched), null, null, typeLabel(matched));
            case "BOTH":
                // 二次确认 + 风险审批都要: 结构照抄 APPROVAL 分支 (同样要带 policyRevision/policyType,
                // PolicyGate.confirmThenApproval() 确认通过后要用它们走 /gate)
                return new Decision(Kind.BOTH, "该策略需二次确认及管理员审批", policyLabel, false, Source.POLICY,
                        policyRevision(matched), null, null, typeLabel(matched));
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
    private static List<PolicyStore.Policy> applicable(List<PolicyStore.Policy> all, long agentId, String hostType, long hostId, ZonedDateTime now) {
        List<PolicyStore.Policy> out = new ArrayList<>();
        for (PolicyStore.Policy p : all) {
            if (!inScope(p, agentId, hostType, hostId, now)) {
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
    private static List<PolicyStore.Policy> ratePolicies(List<PolicyStore.Policy> all, long agentId, String hostType, long hostId, ZonedDateTime now) {
        List<PolicyStore.Policy> out = new ArrayList<>();
        for (PolicyStore.Policy p : all) {
            if (PolicyStore.TYPE_RATE_LIMIT.equals(p.type()) && !p.rulesInvalid() && inScope(p, agentId, hostType, hostId, now)) {
                out.add(p);
            }
        }
        return out;
    }

    /**
     * 策略是否管这次调用: 智能体匹配 (0=全部), 且 (全局且类型匹配) 或 (指定该资源), 且时间段适用
     * <p>
     * now 作为参数传入 (而不是在方法内部取当前时间): 一次判定内所有策略共用同一个时刻, 避免同一次裁决
     * 出现"有的策略按 17:59 判、有的按 18:00 判"; 同时让时间判定变成纯函数, 可测
     */
    private static boolean inScope(PolicyStore.Policy p, long agentId, String hostType, long hostId, ZonedDateTime now) {
        if (!(p.agentIds().contains(0L) || p.agentIds().contains(agentId))) {
            return false;
        }
        boolean global = p.hostIds().contains(0L) && p.hostType() != null && p.hostType().equals(hostType);
        if (!(global || p.hostIds().contains(hostId))) {
            return false;
        }
        // 时间段: 与 agentId/hostId 同层, 不匹配 = 这条策略不适用 (不是"拒绝")
        return inTimeScope(p, now);
    }

    /**
     * 判断"这次调用的时间是否落在该策略的时段内".
     * <p>
     * 三种情况必须区分清楚:
     * <ul>
     *   <li>合法且匹配 → true (策略适用)</li>
     *   <li>合法但不匹配 → false (策略不适用, 移出 applicable —— 这是正常语义)</li>
     *   <li><b>非法 (格式坏 / 空窗口 / 反向区间) → true</b>: 不能返回 false.
     *       返回 false 会让策略被移出 applicable, 从而绕过 rulesInvalid 检查变成"静默丢弃"</li>
     * </ul>
     */
    private static boolean inTimeScope(PolicyStore.Policy p, ZonedDateTime now) {
        String type = p.actionTimeType();
        if ("1".equals(type)) {
            return true;
        }
        // 值域外的 type (含 null) 一律视为非法: 返回 true 留待 rulesInvalid 拒绝.
        // PolicyStore 已保证走到这里的 type 非 null (缺失折成 "1"、非法值直接抛异常),
        // 这里不做 null → "1" 的兜底, 避免漏进的非法 null 静默变成全天生效
        if (!"0".equals(type) && !"2".equals(type)) {
            return true;
        }
        try {
            if ("0".equals(type)) {
                LocalTime start = LocalTime.parse(p.actionTimeStart(), TIME_FORMATTER);
                LocalTime end = LocalTime.parse(p.actionTimeEnd(), TIME_FORMATTER);
                if (start.equals(end)) {
                    // 空窗口: 语义非法. 返回 true 留待 rulesInvalid 拒绝
                    return true;
                }
                // 截断到秒: now 带纳秒, 而解析出的边界纳秒为 0 —— 不截断的话 18:00:00.500 已经
                // isAfter(18:00:00), 闭区间的"结束那一秒"只剩 .000 一个瞬间
                LocalTime t = now.toLocalTime().truncatedTo(ChronoUnit.SECONDS);
                // 跨天: 22:00~06:00 表示 now >= 22:00 或 now <= 06:00
                return start.isAfter(end)
                        ? (!t.isBefore(start) || !t.isAfter(end))
                        : (!t.isBefore(start) && !t.isAfter(end));
            }
            // type=2: 指定绝对时间范围 (单次窗口, 过期后自然不再匹配)
            LocalDateTime start = LocalDateTime.parse(p.actionTimeStart(), DATE_TIME_FORMATTER);
            LocalDateTime end = LocalDateTime.parse(p.actionTimeEnd(), DATE_TIME_FORMATTER);
            if (!start.isBefore(end)) {
                // 反向/零长绝对区间: 语义非法. 同样返回 true 留待 rulesInvalid 拒绝
                return true;
            }
            LocalDateTime t = now.toLocalDateTime().truncatedTo(ChronoUnit.SECONDS);
            return !t.isBefore(start) && !t.isAfter(end);
        } catch (Exception e) {
            // 格式非法 (PolicyStore 已把这类策略标成 rulesInvalid) → 返回 true 让它留在 applicable 里
            // 被 rulesInvalid 拦下拒绝. 这是预期路径而不是"理论上不可达"
            log.warn("策略时间字段解析失败, 交由 rulesInvalid 处理: id={} err={}", p.id(), e.toString());
            return true;
        }
    }

    /**
     * 放行执行时记账: 给这次调用命中的限流策略各 +1
     * <p>
     * 由调用方在**判定为放行之后**调, 只对真正执行的调用计数 (结论 16): 被拒的、弹窗没过的、超限的
     * 都不占配额 —— 否则用被拒命令就能把配额刷满. 授权复检失败那一步在这之后才发生, 那种极少数
     * 情况会多计一次, 是刻意接受的小偏差 (反向"预留再回退"会引入配额泄漏, 更糟)
     */
    public void recordRate(long agentId, String hostType, Long hostId) {
        recordRate(agentId, hostType, hostId, ZonedDateTime.now(BUSINESS_ZONE));
    }

    /** 包级重载: 同样供测试注入时刻 */
    void recordRate(long agentId, String hostType, Long hostId, ZonedDateTime now) {
        if (hostId == null) {
            return;
        }
        // 与 decide() 里的超限判定必须是同一个收敛结果: 只给最高优先级那几条记账,
        // 被盖掉的限流器不累计 —— 否则它在"升回最高优先级"那一刻就带着一堆偷偷攒下的计数直接超限
        for (PolicyStore.Policy p : topPriority(ratePolicies(store.snapshot().policies(), agentId, hostType, hostId, now))) {
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
                // 正则已在 PolicyStore.fetch() 里用 re2j 预编译过一次, 这里直接复用 (线性时间, 不怕 ReDoS)
                return op.pattern() != null && op.pattern().matcher(p.raw()).find();
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

    /**
     * 同类型命中集按优先级收敛: 只留 priority 最小 (数值越小越优先) 的那几条, 保持原顺序
     * <p>
     * 并列 (priority 相等) 时全部保留, 退回原有的合并规则 —— 白名单取最严、黑名单有一条 NONE 即无条件拒.
     * 存量策略优先级全是默认 50, 所以收敛前后行为完全一致.
     * <p>
     * 只作用于**命中集** (matchDeny / matchAllow / ratePolicies 的结果), 不作用于 applicable() 与
     * rulesInvalid 的无条件拒绝: 规则读不出来的策略连类型和意图都不可信, 不能让它被一条高优先级的
     * 同类策略盖掉. 「命中才比较」也保证了高优先级白名单没命中时不会屏蔽掉低优先级白名单
     */
    private static List<PolicyStore.Policy> topPriority(List<PolicyStore.Policy> in) {
        if (in.isEmpty()) {
            return in;
        }
        int min = Integer.MAX_VALUE;
        for (PolicyStore.Policy p : in) {
            min = Math.min(min, p.priority());
        }
        List<PolicyStore.Policy> out = new ArrayList<>();
        for (PolicyStore.Policy p : in) {
            if (p.priority() == min) {
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
     * 拒判基调下的档位: 只要有一条黑名单是 NONE (无条件拒绝)、APPROVAL 或 BOTH, 就不允许直接本人确认放行;
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
            if (MODE_BOTH.equals(m)) {
                out = MODE_BOTH;
            } else if (MODE_APPROVAL.equals(m) && !MODE_BOTH.equals(out)) {
                out = MODE_APPROVAL;
            }
        }
        return out;
    }

    /** 命中集合里是否有策略要求 APPROVAL 或 BOTH (跨策略合并升档用, 不能只认 APPROVAL 而漏判 BOTH) */
    private static boolean requiresApproval(List<PolicyStore.Policy> policies) {
        for (PolicyStore.Policy p : policies) {
            if (MODE_APPROVAL.equals(p.approvalMode()) || MODE_BOTH.equals(p.approvalMode())) {
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

    /**
     * 命中策略的可读标签, 进弹窗、审计与审批单"触发策略"展示
     * <p>
     * 用策略名称 + 规则摘要 (照控制台策略列表页 rulesSummary 同一份计算), 不再是内部 "#id TYPE" ——
     * 后者管理员看不懂命中的具体是什么。规则无效 (rulesSummary 为 null) 时只展示名称
     */
    static String label(List<PolicyStore.Policy> policies) {
        StringBuilder sb = new StringBuilder();
        for (PolicyStore.Policy p : policies) {
            if (sb.length() > 0) {
                sb.append(',');
            }
            sb.append(p.name());
            if (p.rulesSummary() != null && !p.rulesSummary().isBlank()) {
                sb.append('（').append(p.rulesSummary()).append('）');
            }
        }
        return sb.toString();
    }

    /**
     * 命中策略类型的中文标签, 逗号并列去重 (混合命中黑名单+白名单的极端情况, 审批单标题展示用)
     * <p>
     * 用于生成"操作黑名单（主机名）风险审批"这类标题——与 {@link #label} 是两个独立字段:
     * label() 给的是具体策略的名称+规则摘要 (供"触发策略"详情展示), 这里给的是类型大类
     */
    static String typeLabel(List<PolicyStore.Policy> policies) {
        List<String> types = new ArrayList<>();
        for (PolicyStore.Policy p : policies) {
            String t = typeLabel(p.type());
            if (!types.contains(t)) {
                types.add(t);
            }
        }
        return String.join(",", types);
    }

    private static String typeLabel(String type) {
        if (PolicyStore.TYPE_BLACKLIST.equals(type)) {
            return "操作黑名单";
        }
        if (PolicyStore.TYPE_WHITELIST.equals(type)) {
            return "操作白名单";
        }
        return type;
    }

    /**
     * 策略内容摘要 (第二部分, 设计文档 §2.1a): 只摘要**这次裁决实际命中**的策略集合 (matched = deny ∪ allow),
     * 不是全部启用策略——改一条不相关的策略不会让别的在途审批单集体失效。
     * <p>
     * 由网关计算而不是控制台 (与结论 16 的 fingerprint 信任边界不同, 见设计文档说明): 它不是展示给审批人看的内容,
     * 只是一个不透明的失效触发器, 且依赖的命令匹配算法只存在于网关 (parse()/segmentTokens())
     */
    static String policyRevision(List<PolicyStore.Policy> matched) {
        List<PolicyStore.Policy> sorted = new ArrayList<>(matched);
        sorted.sort(Comparator.comparingLong(PolicyStore.Policy::id));
        StringBuilder canonical = new StringBuilder();
        for (PolicyStore.Policy p : sorted) {
            canonical.append(p.id()).append('|').append(p.type()).append('|')
                    .append(p.approvalMode()).append('|').append(p.rulesInvalid()).append('|')
                    // 优先级同理: 改了胜出策略的 priority (或 priority 变动换掉了胜出集合) 都要让在途审批凭证失效.
                    // 被盖掉的那些策略压根不在 matched 里, 改它们的 priority 摘要不变 —— 这是期望语义
                    .append(p.priority()).append('|')
                    // 时间段字段必须算进摘要: 否则改了时间段、快照重拉、新策略生效, 但审批中的旧凭证
                    // 消费时 policyRevision 仍是旧值, 会被误接受
                    .append(p.actionTimeType()).append('|')
                    .append(p.actionTimeStart() == null ? "" : p.actionTimeStart()).append('|')
                    .append(p.actionTimeEnd() == null ? "" : p.actionTimeEnd()).append('|');
            for (PolicyStore.Op op : p.ops()) {
                // （对 Codex 评审的修订）op.value() 是管理员填的任意正则/关键字文本, 可能自带 ':' ';' 这类
                // 分隔符——直接拼接不是单射: 一条 REGEX 值 "x;KEYWORD:y" 和两条 {REGEX,"x"}+{KEYWORD,"y"}
                // 会算出同一段字节, policyRevision 因此可能在规则真的改了之后仍然不变, 让结论 21 的
                // fresh-decide 比对失效。value 长度前缀后再拼: matchType 取自固定小枚举不含 ':', 长度是
                // 十进制数字不含 ':', 随后恰好消费该长度个字符（内容任意）——整条编码因此是无歧义的
                String value = op.value() == null ? "" : op.value();
                canonical.append(op.matchType()).append(':').append(value.length()).append(':').append(value).append(';');
            }
            canonical.append('\n');
        }
        return sha256Hex(canonical.toString());
    }

    private static String sha256Hex(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            // JDK 必带 SHA-256, 走到这里说明环境异常
            throw new IllegalStateException("SHA-256 不可用", e);
        }
    }

    private static String basename(String name) {
        int slash = name.lastIndexOf('/');
        return slash < 0 ? name : name.substring(slash + 1);
    }
}
