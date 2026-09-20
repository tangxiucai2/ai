package com.ai.mcp.policy;

import com.ai.mcp.config.ConsoleClient;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.time.format.ResolverStyle;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * 访问控制策略本地只读快照
 * <p>
 * 心跳带版本号, 变了才拉全量; 心跳连失 3 次 → 策略源不可用 → HOST 命令全拒.
 * <p>
 * 「读到了但为空」与「读不到」必须分开: 前者是「该智能体无策略 → 维持现状放行」,
 * 后者是「策略源不可用 → 全拒」. 两者共用一个布尔就会把故障当成放行.
 * <p>
 * 快照由控制台摊平 (ops 已解析), 网关不认 rules schema —— 将来升到 v3 只改控制台一侧
 */
@Component
public class PolicyStore {

    private static final Logger log = LoggerFactory.getLogger(PolicyStore.class);

    /** 心跳连失阈值, 达到即视为策略源不可用 */
    private static final int FAIL_MAX = 3;

    /** 作用域 id 集合 (hostIds/agentIds) 去重后的条数上限, 与控制台侧同口径 */
    private static final int IDS_MAX = 200;

    public static final String TYPE_WHITELIST = "WHITELIST";
    public static final String TYPE_BLACKLIST = "BLACKLIST";
    /** 频率限制: 网关不执行 (快照里也没有限额字段), 只当它不存在 */
    public static final String TYPE_RATE_LIMIT = "RATE_LIMIT";

    /** 人工介入档位; 未知值按「快照无效」处理, 不能静默降级成 NONE */
    private static final Set<String> APPROVAL_MODES = Set.of("NONE", "CONFIRM", "APPROVAL", "BOTH");

    private static final String REGEX = "REGEX";

    /** 操作项匹配方式的值域; 未知值在 {@code PolicyDecider.governs} 的 switch 里落到 default → 静默不匹配 */
    private static final Set<String> OP_MATCH_TYPES = Set.of("EXACT", "KEYWORD", REGEX);

    /** 时间段控制类型值域: 1全天 0每天固定时段 2指定时间范围段 */
    private static final Set<String> ACTION_TIME_TYPES = Set.of("1", "0", "2");

    /** 优先级值域 (数值越小优先级越高) 与缺字段时的默认值; 与控制台的 @Min(1) @Max(100) 同口径 */
    private static final int PRIORITY_MIN = 1;
    private static final int PRIORITY_MAX = 100;
    private static final int PRIORITY_DEFAULT = 50;

    // 严格解析: 不用默认的 SMART 模式, 否则非法日期可能被自动归整而"看着解析成功";
    // 必须用 uuuu 而不是 yyyy —— 后者是 year-of-era, STRICT 模式下缺 era 字段会直接抛异常,
    // 导致所有合法的 type=2 时间都被判非法 (已用 JDK 实测确认)
    private static final DateTimeFormatter TIME_FORMATTER =
            DateTimeFormatter.ofPattern("HH:mm:ss").withResolverStyle(ResolverStyle.STRICT);
    private static final DateTimeFormatter DATE_TIME_FORMATTER =
            DateTimeFormatter.ofPattern("uuuu-MM-dd HH:mm:ss").withResolverStyle(ResolverStyle.STRICT);

    /** 一条操作项: 命令标识 + 匹配方式 (EXACT/KEYWORD/REGEX) */
    public record Op(String value, String matchType) {
    }

    /**
     * 一条启用中的 HOST 类策略; type=RATE_LIMIT 的不参与黑白名单匹配 (见 {@code PolicyDecider.applicable})
     *
     * @param hostIds      目标资源 id 集合; 单元素 {@code [0]} 是「该 hostType 下全部资源」的哨兵.
     *                     非空, 且 0 不与具体 id 混排 (解析期已保证, 见 {@code fetch})
     * @param agentIds     适用智能体 id 集合; 单元素 {@code [0]} 是「全部智能体」的哨兵. 约束同 hostIds
     * @param name         策略名称 (管理员填写, 展示用, 不参与裁决/policyRevision)
     * @param rulesInvalid 控制台判定规则无效 (存量/人工导入的坏行); 该策略适用范围内一律拒绝, 不当无策略跳过
     * @param rulesSummary 规则内容摘要 (展示用, 不参与裁决/policyRevision); 规则无效时为 null
     * @param limit        仅 RATE_LIMIT: 窗口内次数上限 (有效的限流策略必填, 缺了整次拉取算失败)
     * @param windowSeconds 仅 RATE_LIMIT: 窗口长度 (秒); 非限流类恒 0, 不参与裁决
     * @param actionTimeType  时间段控制: 1全天 0每天固定时段 2指定时间范围段; 缺失字段折成 "1", 存在但非法直接 fetch() 失败
     * @param actionTimeStart 起始时间原值 (可能为 null); type=0 为 HH:mm:ss, type=2 为 uuuu-MM-dd HH:mm:ss;
     *                        非法值不在此处兜底, 交给 {@code PolicyDecider.inTimeScope()} 解析失败 → rulesInvalid 拒绝
     * @param actionTimeEnd   结束时间原值, 格式同 actionTimeStart
     * @param priority        优先级 1~100, 数值越小越优先; 缺失字段折成 {@code 50}, 存在但非法直接 fetch() 失败.
     *                        同类型多条**命中**时只由优先级最高的那几条决定档位 (见 {@code PolicyDecider.topPriority})
     */
    public record Policy(long id, String name, String type, String hostType, List<Long> hostIds, List<Long> agentIds,
                         String approvalMode, boolean rulesInvalid, String rulesSummary, List<Op> ops,
                         long limit, long windowSeconds,
                         String actionTimeType, String actionTimeStart, String actionTimeEnd,
                         int priority) {
    }

    public record Snapshot(String version, List<Policy> policies) {
    }

    private final ConsoleClient console;
    private final ObjectMapper json;

    private volatile Snapshot snapshot = new Snapshot("", List.of());
    /** 是否成功拿到过快照 */
    private volatile boolean loaded;
    /** 连续心跳失败次数 */
    private volatile int fails;

    public PolicyStore(ConsoleClient console, ObjectMapper json) {
        this.console = console;
        this.json = json;
    }

    @PostConstruct
    void register() {
        console.policyHeartbeat(new ConsoleClient.PolicyHeartbeat() {
            @Override
            public void onReport(String version) {
                synced(version);
            }

            @Override
            public void onFail() {
                fails++;
            }
        });
    }

    /**
     * 心跳成功: 版本没变就只清零失败计数, 版本变了才拉快照
     * <p>
     * 同步拉取 (在心跳线程内): 拉完才让 ConsoleClient 置 enabled, 否则「已放行但策略还没到」
     * 有一个窗口期, 该窗口内的 HOST 命令会因为未 loaded 被拒 —— 拒是对的, 但没必要制造这个窗口
     * <p>
     * fails 只在「确实同步成功 / 确实不需要同步」时清零。拉取失败也计数: 心跳通但快照拉不到,
     * 说明新版本(可能是撤权/停用)一直没生效, 旧快照不能无限期沿用 —— 攒够 3 次退到不可用全拒
     */
    private void synced(String version) {
        if (version == null) {
            // 控制台没下发版本 (旧版控制台): 当不可用, 不放行. 部署顺序必须先控制台后网关
            fails++;
            log.warn("控制台未下发策略版本, 策略源按不可用处理");
            return;
        }
        if (loaded && version.equals(snapshot.version())) {
            fails = 0;
            return;
        }
        try {
            Snapshot next = fetch(version);
            snapshot = next;
            loaded = true;
            fails = 0;
            log.info("策略快照已更新 version={} policies={}", next.version(), next.policies().size());
        } catch (Exception e) {
            // 保留旧快照给在途请求用, 但计数不清零 (也不推进 loaded 的版本)
            fails++;
            log.warn("策略快照拉取失败 version={}: {}", version, e.toString());
        }
    }

    /**
     * 包级可见: 允许同包单测直接灌快照数据校验值域/格式, 不必绕心跳 (照 ConsoleClient.applyAuth 同款先例)
     * <p>
     * 快照标签必须用响应自身的 version, 不能用心跳传来的 {@code version} 参数: 心跳报 C 而快照接口因读库延迟/
     * 回滚返回的仍是 B 时代的内容时, 若贴上 C, 此后 {@code version.equals(snapshot.version())} 恒真, 网关会
     * 永久坐在 B 的内容上不再重拉; 同理 B→C→B 回环也会卡住. 贴响应自身的 version 则下一次心跳即发现不等而重拉, 自愈
     */
    Snapshot fetch(String version) throws Exception {
        Map<String, Object> data = console.policySnapshot();
        JsonNode root = json.valueToTree(data);
        JsonNode list = root.path("policies");
        // 必须确认是数组: 缺字段时 path() 会给出 MissingNode, 遍历它等于"空快照",
        // 而空快照会被当成合法的「该智能体没有策略」→ 全量放行. 响应结构不对就得当拉取失败
        if (!list.isArray()) {
            throw new IllegalStateException("策略快照响应缺少 policies 数组");
        }
        // 照缺 policies 同款: 响应结构不对就当拉取失败, 不能拿心跳报的版本号凑一个标签
        JsonNode versionNode = root.path("version");
        if (!versionNode.isTextual() || versionNode.asText().isBlank()) {
            throw new IllegalStateException("策略快照响应缺少 version");
        }
        List<Policy> policies = new ArrayList<>();
        for (JsonNode p : list) {
            // 作用域字段必须齐全: asLong() 对缺字段/ null / 类型不对都静默给 0 —— 结构不对就当整次
            // 拉取失败 (fail-closed), 不能跳过坏条目: 跳过一条黑名单等于弱化它.
            // id 用 isNumber() 不够: 12.9 会被 asLong() 截成 12、超 long 的整数会溢出成另一个真实 id,
            // 都等于"悄悄换了一条策略的身份". 必须是无小数、未溢出的整数 (作用域集合同理, 见 parseIds)
            if (!isExactLong(p.path("id")) || !p.path("type").isTextual() || !p.path("hostType").isTextual()) {
                throw new IllegalStateException("策略快照条目缺少基础字段: " + p);
            }
            List<Long> hostIds = parseIds(p, "hostIds");
            List<Long> agentIds = parseIds(p, "agentIds");
            // name 展示用但要求非空: 控制台表结构本就 NOT NULL, 缺失说明快照结构不对, 同一套 fail-closed 口径
            if (!p.path("name").isTextual() || p.path("name").asText().isBlank()) {
                throw new IllegalStateException("策略快照条目缺少 name: " + p);
            }
            // 档位值必须在值域内: 上层的 indexOf 对未知值给 -1, 会被静默降级成 NONE ——
            // 未来控制台加了新档位 (或写错) 时, 本该确认/审批的命令会直接放行
            if (!p.path("approvalMode").isTextual() || !APPROVAL_MODES.contains(p.path("approvalMode").asText())) {
                throw new IllegalStateException("策略快照条目的 approvalMode 不在值域内: " + p);
            }
            String type = p.path("type").asText("");
            // 严格布尔: asBoolean(false) 会把「字段缺失/类型不对」读成"规则有效", 配上 agentIds=[0]
            // 就是「全部智能体一律放行」—— 与 fail-closed 组合相反, 结构不对一律整次拉取失败
            JsonNode invalidNode = p.path("rulesInvalid");
            if (!invalidNode.isBoolean()) {
                throw new IllegalStateException("策略快照条目的 rulesInvalid 不是布尔: " + p);
            }
            boolean invalid = invalidNode.booleanValue();
            // 时间段控制: path() 对不存在的字段返回 MissingNode —— 老控制台的快照条目根本没有这三个属性.
            // 老控制台的真实形态是三字段**全部**缺失; "type 缺失但 start/end 存在"这种混合形态只可能是
            // 控制台侧序列化/映射 bug (新控制台受 @JsonInclude(ALWAYS) 约束三字段要么全出现要么全不出现),
            // 必须硬失败而不是兼容成全天
            JsonNode timeTypeNode = p.path("actionTimeType");
            JsonNode timeStartNode = p.path("actionTimeStart");
            JsonNode timeEndNode = p.path("actionTimeEnd");
            String actionTimeType;
            if (timeTypeNode.isMissingNode() && timeStartNode.isMissingNode() && timeEndNode.isMissingNode()) {
                actionTimeType = "1";                      // 老控制台: 按全天处理 (网关先上线时的兼容路径)
            } else if (!timeTypeNode.isTextual() || !ACTION_TIME_TYPES.contains(timeTypeNode.asText())) {
                // 存在但非法 (含显式 JSON null、空串、数字、布尔、未知文本、混合缺失形态) —— 全部硬失败
                throw new IllegalStateException("策略快照条目的 actionTimeType 不在值域内: " + p);
            } else {
                actionTimeType = timeTypeNode.asText();
            }
            // 时间字段非法 (不能解析/区间反了/起止相等) 的策略, 也按"规则无效"处理:
            // 不能静默丢弃(弱化黑名单)、不能让整条快照失败(代价过大)、不能当全天生效(fail-open)
            if (!actionTimeValid(actionTimeType, p)) {
                invalid = true;
            }
            // 优先级: 缺字段折默认 50 (老控制台快照没有这一列), 存在但非法硬失败 —— 见 parsePriority
            int priority = parsePriority(p);
            // 限流也一样: 缺 limit/windowSeconds 会被读成「不限」, 等于限流静默失效
            if (TYPE_RATE_LIMIT.equals(type) && !invalid
                    && !(p.path("limit").isNumber() && p.path("windowSeconds").isNumber())) {
                throw new IllegalStateException("限流策略缺少 limit/windowSeconds: " + p);
            }
            JsonNode opsNode = p.path("ops");
            // ops 本身缺失/不是数组 (跟单项缺字段是同一类问题, 同一套口径): 缺字段时 path() 给出
            // MissingNode, 遍历它悄悄等于空列表 —— rulesInvalid=false 的黑名单会被读成"零条 deny",
            // 静默失效. invalid=true 的策略整体按拒绝处理, ops 内容不影响裁决, 不必牵连整次拉取失败
            if (!opsNode.isArray() && !invalid) {
                throw new IllegalStateException("策略快照条目的 ops 缺失或不是数组: " + p);
            }
            List<Op> ops = new ArrayList<>();
            for (JsonNode o : opsNode) {
                JsonNode valueNode = o.path("value");
                JsonNode matchTypeNode = o.path("matchType");
                if (!valueNode.isTextual() || !matchTypeNode.isTextual()) {
                    // rulesInvalid=false 却有一项读不出来 (缺字段/类型不对): 跟前面几个字段同一套口径 ——
                    // 静默丢掉这一项等于弱化了这条黑名单 (少一项 deny, 后面一条白名单命中就变成放行了).
                    // invalid=true 的策略本就整体拒绝, ops 内容不影响裁决, 不必为它牵连整次拉取失败
                    if (!invalid) {
                        throw new IllegalStateException("策略快照条目的操作项缺少 value/matchType: " + p);
                    }
                    continue;
                }
                String opValue = valueNode.asText();
                String matchType = matchTypeNode.asText();
                // matchType 不在值域内 (或 REGEX 语法编译不过) 是同一类"语义上读不出来": 交给
                // PolicyDecider 的话, governs() 的 switch 落到 default 就是静默"不匹配" ——
                // 黑名单少一项 deny, 这项要么在这里直接堵掉, 要么整个策略按拒绝处理 (跟上面同一套口径)
                if (!OP_MATCH_TYPES.contains(matchType) || (REGEX.equals(matchType) && !isValidRegex(opValue))) {
                    if (!invalid) {
                        throw new IllegalStateException("策略快照条目的操作项无法解析 (matchType 未知或正则语法错误): " + p);
                    }
                    continue;
                }
                ops.add(new Op(opValue, matchType));
            }
            // rulesSummary 展示用可空 (规则无效时控制台本就不下发有意义的摘要), 不必牵连整次拉取失败
            String rulesSummary = p.path("rulesSummary").isTextual() ? p.path("rulesSummary").asText() : null;
            // actionTimeStart/End 保留**原值**(可能为 null): 非法的那些已由 actionTimeValid 标成 invalid,
            // 保留原值可以让 Decider 的解析失败走 catch → return true → 交由 rulesInvalid 拒绝.
            // 不要把非法策略的 actionTimeType 折成 "1" —— 那样 inTimeScope() 会直接放行该策略(全天),
            // 整条 fail-closed 链路失效
            policies.add(new Policy(p.path("id").asLong(), p.path("name").asText(), type, p.path("hostType").asText(""),
                    hostIds, agentIds,
                    p.path("approvalMode").asText("NONE"), invalid, rulesSummary,
                    List.copyOf(ops),
                    p.path("limit").asLong(), p.path("windowSeconds").asLong(),
                    actionTimeType,
                    timeStartNode.isTextual() ? timeStartNode.asText() : null,
                    timeEndNode.isTextual() ? timeEndNode.asText() : null,
                    priority));
        }
        return new Snapshot(versionNode.asText(), List.copyOf(policies));
    }

    /**
     * 优先级: 照 actionTimeType 同一套兼容口径 —— 字段缺失 (老控制台快照没有这一列) 折成默认 50,
     * 存在但非法 (显式 null / 浮点 / 字符串 / 超 int / 越界) 一律整次拉取失败
     * <p>
     * 非法值不能静默折成 50: 优先级决定同类型策略谁说了算, 折默认等于把管理员排好的次序悄悄改掉 ——
     * 一条本该盖住别人的黑名单会突然并列, 或反过来被别人盖掉
     */
    private static int parsePriority(JsonNode p) {
        JsonNode node = p.path("priority");
        if (node.isMissingNode()) {
            return PRIORITY_DEFAULT;
        }
        // isIntegralNumber()+canConvertToInt() 缺一不可: 前者挡掉 12.9 被 asInt() 截成 12,
        // 后者挡掉超 int 的整数溢出成另一个档位 (同 isExactLong 的理由)
        if (!node.isIntegralNumber() || !node.canConvertToInt()
                || node.intValue() < PRIORITY_MIN || node.intValue() > PRIORITY_MAX) {
            throw new IllegalStateException("策略快照条目的 priority 不在值域内: " + p);
        }
        return node.intValue();
    }

    /** JSON 数字是否是无小数、未溢出的整数; isNumber()+asLong() 会把 12.9 截成 12、把超 long 溢出成另一个 id */
    private static boolean isExactLong(JsonNode n) {
        return n.isIntegralNumber() && n.canConvertToLong();
    }

    /**
     * 作用域 id 集合 (hostIds 目标资源 / agentIds 适用智能体): 必须是非空数组, 每个元素都是 >=0 的
     * 精确整数; 0 是「全部」哨兵, 只许独占整个数组; 去重保序后不得超过 {@link #IDS_MAX} (与控制台同口径)
     * <p>
     * 缺失/非数组/空数组都不能折成"全部"或"跳过这条策略" —— 0 是放大授权, 跳过则是弱化黑名单.
     * 一律按整次拉取失败处理 (fail-closed, 沿用旧快照, 连失 3 次退到不可用全拒)
     */
    private static List<Long> parseIds(JsonNode p, String field) {
        JsonNode node = p.path(field);
        if (!node.isArray() || node.isEmpty()) {
            throw new IllegalStateException("策略快照条目的 " + field + " 非法: " + p);
        }
        // LinkedHashSet 去重保序: 控制台侧已去重, 网关不跨进程信任它 (上限按去重后的规模判)
        Set<Long> ids = new LinkedHashSet<>();
        for (JsonNode e : node) {
            if (!isExactLong(e) || e.asLong() < 0) {
                throw new IllegalStateException("策略快照条目的 " + field + " 非法: " + p);
            }
            ids.add(e.asLong());
        }
        // [0, 12] 这种混排语义不明 (是全部还是只有 12?), 控制台侧不该产出; 按哨兵解读就是放大授权
        if (ids.contains(0L) && ids.size() > 1) {
            throw new IllegalStateException("策略快照条目的 " + field + " 非法: " + p);
        }
        if (ids.size() > IDS_MAX) {
            throw new IllegalStateException("策略快照条目的 " + field + " 非法: " + p);
        }
        return List.copyOf(ids);
    }

    /**
     * REGEX 操作项的值是否真的能编译
     * <p>
     * 控制台侧当前的值域校验 (HOST_CMD 字符集) 三种 matchType 共用同一套, 理论上已经堵住了非法正则语法
     * —— 但网关不跨进程信任这个约束: 万一存量数据、人工导入、或控制台校验改了口径, 一条编译不过的
     * 正则不该被 governs() 的 switch 落到 default 静默当"不匹配", 那样一条黑名单会悄悄消失
     */
    private static boolean isValidRegex(String regex) {
        try {
            Pattern.compile(regex);
            return true;
        } catch (PatternSyntaxException e) {
            return false;
        }
    }

    /**
     * type=0 要求两个合法 HH:mm:ss 且不相等 (跨天合法, 方向不在这里判, 交给 PolicyDecider.inTimeScope());
     * type=2 要求两个合法 uuuu-MM-dd HH:mm:ss 且 start < end; type=1 不看时间字段
     */
    private static boolean actionTimeValid(String type, JsonNode p) {
        if ("1".equals(type)) {
            return true;
        }
        String startRaw = p.path("actionTimeStart").asText(null);
        String endRaw = p.path("actionTimeEnd").asText(null);
        try {
            if ("0".equals(type)) {
                LocalTime start = LocalTime.parse(startRaw, TIME_FORMATTER);
                LocalTime end = LocalTime.parse(endRaw, TIME_FORMATTER);
                // start == end 是空窗口 (无意义配置), 按非法处理
                return !start.equals(end);
            }
            LocalDateTime start = LocalDateTime.parse(startRaw, DATE_TIME_FORMATTER);
            LocalDateTime end = LocalDateTime.parse(endRaw, DATE_TIME_FORMATTER);
            // 绝对区间必须正向; 反向/零长区间是配置错误
            return start.isBefore(end);
        } catch (Exception e) {
            return false;
        }
    }

    /** 策略源是否不可用 (心跳连失 FAIL_MAX 次, 或从未成功拉到过快照) */
    public boolean unavailable() {
        return fails >= FAIL_MAX || !loaded;
    }

    public Snapshot snapshot() {
        return snapshot;
    }

    /** 供节点自查与验收观察 */
    public int failCount() {
        return fails;
    }
}
