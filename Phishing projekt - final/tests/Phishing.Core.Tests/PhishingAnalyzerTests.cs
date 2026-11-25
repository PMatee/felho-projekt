using Phishing.Core;
using Xunit;

namespace Phishing.Core.Tests;

public class PhishingAnalyzerTests
{
    private static HashSet<string> Rules(AnalysisResult result) =>
        result.Findings.Select(f => f.Rule).ToHashSet();

    [Fact]
    public void LegitEmail_IsLowRisk()
    {
        var result = PhishingAnalyzer.Analyze(new EmailInput
        {
            Sender = "Kovács Anna <anna@ceg.hu>",
            Subject = "Heti megbeszélés",
            Body = "Szia Péter, holnap 10-kor találkozunk a tárgyalóban. Anna",
            Auth = new() { ["spf"] = "pass", ["dkim"] = "pass", ["dmarc"] = "pass" },
        });

        Assert.Equal("alacsony", result.RiskLevel);
        Assert.Equal(0, result.RiskScore);
    }

    [Fact]
    public void ClassicPhishing_IsHighRisk()
    {
        var result = PhishingAnalyzer.Analyze(new EmailInput
        {
            Sender = "PayPal Support <help@paypa1-secure.xyz>",
            ReplyTo = "collect@mailbox.top",
            Subject = "Sürgős: fiókját felfüggesztjük!",
            Body = "Kedves ügyfelünk, azonnal adja meg a jelszavát: "
                 + "<a href=\"http://192.168.4.5/login\">www.paypal.com</a>",
            Attachments = new() { "szamla.pdf.exe" },
            Auth = new() { ["spf"] = "fail", ["dkim"] = "fail" },
        });

        Assert.Equal("magas", result.RiskLevel);
        Assert.Equal(100, result.RiskScore);

        var expected = new[]
        {
            "URGENCY_LANGUAGE", "CREDENTIAL_REQUEST", "IP_URL", "LINK_TEXT_MISMATCH",
            "DOUBLE_EXTENSION", "AUTH_FAIL", "LOOKALIKE_DOMAIN", "SENDER_NAME_MISMATCH",
            "REPLY_TO_MISMATCH",
        };
        Assert.Subset(Rules(result), expected.ToHashSet());
    }

    [Fact]
    public void UrlShortener_AndPlainHttp_AreFlagged()
    {
        var result = PhishingAnalyzer.Analyze(new EmailInput
        {
            Subject = "Nézd meg",
            Body = "http://bit.ly/abc123",
        });

        Assert.Contains("URL_SHORTENER", Rules(result));
        Assert.Contains("HTTP_NO_TLS", Rules(result));
    }

    [Fact]
    public void OfficialDomain_IsNotLookalike()
    {
        var result = PhishingAnalyzer.Analyze(new EmailInput
        {
            Sender = "PayPal <service@paypal.com>",
            Body = "https://www.paypal.com/hu",
        });

        Assert.DoesNotContain("LOOKALIKE_DOMAIN", Rules(result));
        Assert.DoesNotContain("SENDER_NAME_MISMATCH", Rules(result));
    }

    [Fact]
    public void Score_IsCappedAt100()
    {
        var body = "password " + string.Join(" ", Enumerable.Range(0, 30).Select(i => $"http://1.2.3.{i}/x"));
        var result = PhishingAnalyzer.Analyze(new EmailInput
        {
            Subject = "urgent immediately",
            Body = body,
            Attachments = new() { "a.exe", "b.scr", "c.bat" },
        });

        Assert.True(result.RiskScore <= 100);
    }

    [Fact]
    public void PunycodeAndAtSign_AreFlagged()
    {
        var result = PhishingAnalyzer.Analyze(new EmailInput
        {
            Body = "http://xn--pypal-4ve.com/ és http://bank.hu@evil.example/",
        });

        Assert.Contains("PUNYCODE_URL", Rules(result));
        Assert.Contains("AT_IN_URL", Rules(result));
    }

    [Fact]
    public void AuthKeys_AreCaseInsensitive_AndDuplicatesDoNotThrow()
    {
        var result = PhishingAnalyzer.Analyze(new EmailInput
        {
            Subject = "teszt",
            Auth = new() { ["SPF"] = "FAIL", ["spf"] = "fail" },
        });

        Assert.Contains("AUTH_FAIL", Rules(result));
    }
}
