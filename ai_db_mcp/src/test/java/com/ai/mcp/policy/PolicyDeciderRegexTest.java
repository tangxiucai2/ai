package com.ai.mcp.policy;

import com.google.re2j.Matcher;
import com.google.re2j.Pattern;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * PolicyDecider KEYWORD/REGEX 命中语义单测
 * (设计文档 2026-09-21-访问控制策略-HOST命令规则放宽正则关键词值域 §4.2 网关侧).
 * <p>
 * REGEX 走 re2j (线性时间, 不怕 ReDoS) 且在 PolicyStore.fetch() 阶段预编译好;
 * 这里直接构造 Op 打 hitDeny(), 钉住两件事: 引擎换成 re2j 后哪些正则仍然命中,
 * 以及 re2j 与 java.util.regex 语义不同的那几处 ((?U) 是 ungreedy 不是 unicode, \123 是八进制转义)
 */
class PolicyDeciderRegexTest {

    private static PolicyStore.Op regex(String value) {
        return new PolicyStore.Op(value, "REGEX", Pattern.compile(value));
    }

    private static PolicyStore.Op keyword(String value) {
        return new PolicyStore.Op(value, "KEYWORD", null);
    }

    private static boolean hit(PolicyStore.Op op, String command) {
        return PolicyDecider.hitDeny(op, PolicyDecider.parse(command));
    }

    private static final String READ_SHADOW = "\\b(cat|less)\\b.*/etc/(passwd|shadow)";

    @Test
    void blacklistRegexHitsDirectRead() {
        assertTrue(hit(regex(READ_SHADOW), "cat /etc/shadow"));
    }

    // 包装词 (sudo/env/...) 不该绕过正则: REGEX 作用在整条原始命令串上
    @Test
    void blacklistRegexHitsWrappedRead() {
        assertTrue(hit(regex(READ_SHADOW), "sudo cat /etc/shadow"));
    }

    @Test
    void blacklistRegexMissesOtherFile() {
        assertFalse(hit(regex(READ_SHADOW), "cat /etc/hosts"));
    }

    @Test
    void keywordHitsSubstring() {
        assertTrue(hit(keyword("/etc/shadow"), "cat /etc/shadow"));
    }

    @Test
    void keywordMissesWhenSubstringAbsent() {
        assertFalse(hit(keyword("/etc/shadow"), "cat shadow.txt"));
    }

    // re2j 的 \w 只认 ASCII, (?U) 是 ungreedy 修饰符而**不是** unicode 开关 ——
    // 拿 java.util.regex 的直觉写策略会写出一条根本拦不住中文的规则
    @Test
    void asciiWordClassDoesNotMatchChinese() {
        assertFalse(hit(regex("^(?U)\\w+$"), "中文"));
    }

    // \123 在 RE2 里是八进制转义 (0123 = 'S'), 不是反向引用
    @Test
    void octalEscapeMatchesLiteralChar() {
        assertTrue(hit(regex("\\123"), "ls -S"));
    }

    // (?U) 把 .* 变成非贪婪: a1b2b 上取到的是最短的 a1b
    @Test
    void ungreedyFlagTakesShortestMatch() {
        Matcher m = Pattern.compile("(?U)a.*b").matcher("a1b2b");
        assertTrue(m.find());
        assertEquals("a1b", m.group());
    }
}
