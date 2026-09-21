package com.ai.mcp.policy;

import com.ai.mcp.config.ConsoleClient;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * PolicyStore 操作项值域与正则预编译单测
 * (设计文档 2026-09-21-访问控制策略-HOST命令规则放宽正则关键词值域 §4.2 网关自校验值域 / 网关预编译 fail-closed 路径).
 * <p>
 * 网关不跨进程信任控制台的校验: 值域三端必须一字不差, 且一条读不出来的操作项绝不能被静默丢掉 ——
 * 黑名单少一项 deny, 后面一条白名单命中就变成放行了。所以 rulesInvalid=false 时坏项让整次拉取失败,
 * rulesInvalid=true 时策略本就整体拒绝, 坏项跳过不牵连拉取
 */
class PolicyStoreOpValueTest {

    private static final String EXACT = "EXACT";
    private static final String KEYWORD = "KEYWORD";
    private static final String REGEX = "REGEX";

    /** 值域上限内/外的填充串: 'a' 重复 n 次 */
    private static String repeat(int n) {
        return new String(new char[n]).replace('\0', 'a');
    }

    // ---- validOpValue: EXACT 窄字符集 ----

    @Test
    void exactPlainCommandAccepted() {
        assertTrue(PolicyStore.validOpValue("cat", EXACT));
    }

    // EXACT 是命令名不是命令行: 带斜杠的路径落在窄字符集之外
    @Test
    void exactPathRejected() {
        assertFalse(PolicyStore.validOpValue("/bin/cat", EXACT));
    }

    @Test
    void exactAtUpperBoundAccepted() {
        assertTrue(PolicyStore.validOpValue(repeat(64), EXACT));
    }

    @Test
    void exactOverUpperBoundRejected() {
        assertFalse(PolicyStore.validOpValue(repeat(65), EXACT));
    }

    // EXACT 不跟着 KEYWORD 一起放宽: 空格/斜杠仍然拒
    @Test
    void exactWithSpaceRejected() {
        assertFalse(PolicyStore.validOpValue("rm -rf /", EXACT));
    }

    // ---- validOpValue: KEYWORD/REGEX 放宽到可打印 ASCII ----

    @Test
    void keywordPathAccepted() {
        assertTrue(PolicyStore.validOpValue("/etc/shadow", KEYWORD));
    }

    @Test
    void keywordWithSpacesAccepted() {
        assertTrue(PolicyStore.validOpValue("rm -rf /", KEYWORD));
    }

    // 连续空格是合法内容 (摘要展示侧也按原样保留), 只有首尾空格才拒
    @Test
    void keywordConsecutiveSpacesAccepted() {
        assertTrue(PolicyStore.validOpValue("a  b", KEYWORD));
    }

    @Test
    void keywordAtUpperBoundAccepted() {
        assertTrue(PolicyStore.validOpValue(repeat(256), KEYWORD));
    }

    @Test
    void keywordOverUpperBoundRejected() {
        assertFalse(PolicyStore.validOpValue(repeat(257), KEYWORD));
    }

    @Test
    void emptyValueRejected() {
        assertFalse(PolicyStore.validOpValue("", KEYWORD));
    }

    @Test
    void nullValueRejected() {
        assertFalse(PolicyStore.validOpValue(null, KEYWORD));
    }

    // 首尾空格是裁剪失误的常见形态, 且在 KEYWORD 场景没有意义
    @Test
    void singleSpaceRejected() {
        assertFalse(PolicyStore.validOpValue(" ", KEYWORD));
    }

    @Test
    void leadingSpaceRejected() {
        assertFalse(PolicyStore.validOpValue(" a", KEYWORD));
    }

    @Test
    void trailingSpaceRejected() {
        assertFalse(PolicyStore.validOpValue("a ", KEYWORD));
    }

    @Test
    void nonAsciiRejected() {
        assertFalse(PolicyStore.validOpValue("中", KEYWORD));
    }

    @Test
    void tabRejected() {
        assertFalse(PolicyStore.validOpValue("a\tb", KEYWORD));
    }

    // \x7F (DEL) 在 \x20-\x7E 之外: 不可见字符一律拒, 否则策略值肉眼无法核对
    @Test
    void delCharRejected() {
        assertFalse(PolicyStore.validOpValue("ab", KEYWORD));
    }

    // NBSP 看起来就是个空格, 但不是 \x20: 放进来会造成"明明一样却不匹配"
    @Test
    void nbspRejected() {
        assertFalse(PolicyStore.validOpValue("a b", KEYWORD));
    }

    @Test
    void unknownMatchTypeRejected() {
        assertFalse(PolicyStore.validOpValue("cat", "FOO"));
    }

    // REGEX 与 KEYWORD 共用字符集; 语法对不对是下一道 compileRegex 的事, 不在这里判
    @Test
    void regexSharesKeywordCharset() {
        assertTrue(PolicyStore.validOpValue("\\b(cat|less)\\b.*/etc/(passwd|shadow)", REGEX));
        assertTrue(PolicyStore.validOpValue("(", REGEX), "语法非法但字符集合法, 应由 compileRegex 拦下");
    }

    // ---- fetch() 级: 正则预编译 (compileRegex 是 private, 经 Op.pattern() 观测) ----

    private static PolicyStore newStore(Map<String, Object> snapshotData) {
        ConsoleClient console = new ConsoleClient() {
            @Override
            public Map<String, Object> policySnapshot() {
                return snapshotData;
            }
        };
        return new PolicyStore(console, new ObjectMapper());
    }

    private static Map<String, Object> snapshotWithOp(String value, String matchType, boolean rulesInvalid) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("id", 1L);
        p.put("name", "测试策略");
        p.put("type", PolicyStore.TYPE_BLACKLIST);
        p.put("hostType", "SSH");
        p.put("hostIds", List.of(0));
        p.put("agentIds", List.of(0));
        p.put("approvalMode", "NONE");
        p.put("rulesInvalid", rulesInvalid);
        p.put("ops", List.of(Map.of("value", value, "matchType", matchType)));
        return Map.of("version", "v1", "policies", List.of(p));
    }

    private static List<PolicyStore.Op> opsOf(String value, String matchType, boolean rulesInvalid) throws Exception {
        return newStore(snapshotWithOp(value, matchType, rulesInvalid)).fetch("v1").policies().get(0).ops();
    }

    /** rulesInvalid=false 时坏项必须让整次拉取失败, rulesInvalid=true 时该项被跳过且不进 ops */
    private static void assertOpRejected(String value, String matchType) throws Exception {
        PolicyStore strict = newStore(snapshotWithOp(value, matchType, false));
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> strict.fetch("v1"),
                () -> matchType + " " + value + " 应当让整次拉取失败");
        assertTrue(e.getMessage().startsWith("策略快照条目的操作项无法解析"), e.getMessage());
        assertTrue(opsOf(value, matchType, true).isEmpty(), "rulesInvalid=true 时坏项应被跳过而不是进入 ops");
    }

    @Test
    void validRegexCompiledOnce() throws Exception {
        List<PolicyStore.Op> ops = opsOf("(?i)cat", REGEX, false);
        assertEquals(1, ops.size());
        assertNotNull(ops.get(0).pattern(), "合法正则应在 fetch() 阶段编译好供 PolicyDecider 复用");
    }

    @Test
    void wordBoundaryRegexCompiles() throws Exception {
        assertNotNull(opsOf("\\b(cat|less)\\b.*/etc/(passwd|shadow)", REGEX, false).get(0).pattern());
    }

    // \123 是 RE2 的八进制转义 (= 'S'), 不是反向引用: 必须编译通过
    @Test
    void octalEscapeRegexCompiles() throws Exception {
        assertNotNull(opsOf("\\123", REGEX, false).get(0).pattern());
    }

    // 非 REGEX 的 pattern 恒为 null: PolicyDecider 只在 REGEX 分支用它
    @Test
    void nonRegexOpHasNullPattern() throws Exception {
        assertNull(opsOf("/etc/shadow", KEYWORD, false).get(0).pattern());
        assertNull(opsOf("cat", EXACT, false).get(0).pattern());
    }

    @Test
    void unbalancedParenRegexRejected() throws Exception {
        assertOpRejected("(", REGEX);
    }

    // RE2 线性时间引擎不支持反向引用
    @Test
    void backreferenceRegexRejected() throws Exception {
        assertOpRejected("(a)\\1", REGEX);
    }

    // 不支持环视
    @Test
    void lookaheadRegexRejected() throws Exception {
        assertOpRejected("(?=a)", REGEX);
    }

    // 不支持占有量词
    @Test
    void possessiveQuantifierRegexRejected() throws Exception {
        assertOpRejected("a++", REGEX);
    }

    // 不支持原子组
    @Test
    void atomicGroupRegexRejected() throws Exception {
        assertOpRejected("(?>a)", REGEX);
    }

    // ---- fetch() 级: 值域非法与 rulesInvalid 的配合 ----

    @Test
    void badKeywordValueRejected() throws Exception {
        assertOpRejected(" ", KEYWORD);
    }

    @Test
    void unknownMatchTypeOpRejected() throws Exception {
        assertOpRejected("cat", "FOO");
    }

    @Test
    void overLongKeywordOpRejected() throws Exception {
        assertOpRejected(repeat(257), KEYWORD);
    }

    // 合法项照常进 ops: 否则上面那些"应被跳过"的断言可能只是因为整条策略压根没解析出来
    @Test
    void validKeywordOpKept() throws Exception {
        List<PolicyStore.Op> ops = opsOf("rm -rf /", KEYWORD, false);
        assertEquals(1, ops.size());
        assertEquals("rm -rf /", ops.get(0).value());
        assertEquals(KEYWORD, ops.get(0).matchType());
    }

    // rulesInvalid=true 跳过坏项后快照仍然可用 (fail-closed 只作用在 rulesInvalid=false 上)
    @Test
    void invalidPolicySnapshotStillLoads() throws Exception {
        PolicyStore.Snapshot snap = newStore(snapshotWithOp("(a)\\1", REGEX, true)).fetch("v1");
        assertEquals(1, snap.policies().size());
        assertTrue(snap.policies().get(0).rulesInvalid());
        assertTrue(snap.policies().get(0).ops().isEmpty(), "坏正则被跳过后 ops 应为空, 策略仍按 rulesInvalid 整体拒绝");
    }
}
