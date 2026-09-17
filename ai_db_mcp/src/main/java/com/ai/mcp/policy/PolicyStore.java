package com.ai.mcp.policy;

import com.ai.mcp.config.ConsoleClient;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
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

    public static final String TYPE_WHITELIST = "WHITELIST";
    public static final String TYPE_BLACKLIST = "BLACKLIST";
    /** 频率限制: 网关不执行 (快照里也没有限额字段), 只当它不存在 */
    public static final String TYPE_RATE_LIMIT = "RATE_LIMIT";

    /** 人工介入档位; 未知值按「快照无效」处理, 不能静默降级成 NONE */
    private static final Set<String> APPROVAL_MODES = Set.of("NONE", "CONFIRM", "APPROVAL");

    private static final String REGEX = "REGEX";

    /** 操作项匹配方式的值域; 未知值在 {@code PolicyDecider.governs} 的 switch 里落到 default → 静默不匹配 */
    private static final Set<String> OP_MATCH_TYPES = Set.of("EXACT", "KEYWORD", REGEX);

    /** 一条操作项: 命令标识 + 匹配方式 (EXACT/KEYWORD/REGEX) */
    public record Op(String value, String matchType) {
    }

    /**
     * 一条启用中的 HOST 类策略; type=RATE_LIMIT 的不参与黑白名单匹配 (见 {@code PolicyDecider.applicable})
     *
     * @param name         策略名称 (管理员填写, 展示用, 不参与裁决/policyRevision)
     * @param rulesInvalid 控制台判定规则无效 (存量/人工导入的坏行); 该策略适用范围内一律拒绝, 不当无策略跳过
     * @param rulesSummary 规则内容摘要 (展示用, 不参与裁决/policyRevision); 规则无效时为 null
     * @param limit        仅 RATE_LIMIT: 窗口内次数上限 (有效的限流策略必填, 缺了整次拉取算失败)
     * @param windowSeconds 仅 RATE_LIMIT: 窗口长度 (秒); 非限流类恒 0, 不参与裁决
     */
    public record Policy(long id, String name, String type, String hostType, long hostId, long agentId,
                         String approvalMode, boolean rulesInvalid, String rulesSummary, List<Op> ops,
                         long limit, long windowSeconds) {
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

    private Snapshot fetch(String version) throws Exception {
        Map<String, Object> data = console.policySnapshot();
        JsonNode root = json.valueToTree(data);
        JsonNode list = root.path("policies");
        // 必须确认是数组: 缺字段时 path() 会给出 MissingNode, 遍历它等于"空快照",
        // 而空快照会被当成合法的「该智能体没有策略」→ 全量放行. 响应结构不对就得当拉取失败
        if (!list.isArray()) {
            throw new IllegalStateException("策略快照响应缺少 policies 数组");
        }
        List<Policy> policies = new ArrayList<>();
        for (JsonNode p : list) {
            // 作用域字段必须齐全: asLong() 对缺字段/ null / 类型不对都静默给 0, 而 0 是「全部智能体 /
            // 全部资源」的哨兵 —— 一条本该只管某个智能体的策略会变成管所有智能体, 这是放大授权.
            // 结构不对就当整次拉取失败 (fail-closed), 不能跳过坏条目: 跳过一条黑名单等于弱化它
            if (!p.path("id").isNumber() || !p.path("type").isTextual() || !p.path("hostType").isTextual()
                    || !p.path("hostId").isNumber() || !p.path("agentId").isNumber()) {
                throw new IllegalStateException("策略快照条目缺少作用域字段: " + p);
            }
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
            boolean invalid = p.path("rulesInvalid").asBoolean(false);
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
            policies.add(new Policy(p.path("id").asLong(), p.path("name").asText(), type, p.path("hostType").asText(""),
                    p.path("hostId").asLong(), p.path("agentId").asLong(),
                    p.path("approvalMode").asText("NONE"), invalid, rulesSummary,
                    List.copyOf(ops),
                    p.path("limit").asLong(), p.path("windowSeconds").asLong()));
        }
        return new Snapshot(version, List.copyOf(policies));
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
