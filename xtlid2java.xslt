<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:output method="text" />

    <xsl:template match="/">
        <xsl:text>package xbeloader;&#xa;</xsl:text>
        <xsl:text>&#xa;</xsl:text>
        <xsl:text>import java.util.HashMap;&#xa;</xsl:text>
        <xsl:text>import java.util.Map;&#xa;</xsl:text>
        <xsl:text>&#xa;</xsl:text>
        <xsl:text>public class XbeXtlidDb {&#xa;</xsl:text>
        <xsl:text>    public static final Map&lt;Long, String[]&gt; xtlids;&#xa;</xsl:text>
        <xsl:text>&#xa;</xsl:text>
        <xsl:text>    static {&#xa;</xsl:text>
        <xsl:text>        xtlids = new HashMap&lt;&gt;();&#xa;</xsl:text>

        <xsl:apply-templates select="//lib"/>

        <xsl:text>    }&#xa;</xsl:text>
        <xsl:text>}&#xa;</xsl:text>
    </xsl:template>

    <xsl:template match="lib">
        <xsl:apply-templates select="func"/>
    </xsl:template>

     <xsl:template match="func">
        <xsl:text>        xtlids.put(</xsl:text>
        <xsl:value-of select="@id"/>
        <xsl:text>L, new String[]{"</xsl:text>
        <xsl:value-of select="../@name"/>
        <xsl:text>", "</xsl:text>
        <xsl:value-of select="@name"/>
        <xsl:text>"});&#xa;</xsl:text>
    </xsl:template>
</xsl:stylesheet>
