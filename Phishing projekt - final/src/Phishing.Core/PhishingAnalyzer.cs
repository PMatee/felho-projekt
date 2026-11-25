using System.Text.RegularExpressions;

namespace Phishing.Core;

/// <summary>
/// Szabályalapú phishing-elemző. Nem függ az Azure-tól, így önállóan tesztelhető.
/// Kimenet: kockázati pontszám (0-100), szint és a felismert gyanús jellemzők listája.
/// </summary>
public static class PhishingAnalyzer
{
    // ------------------------------------------------------------ konfiguráció

    private static readonly string[] UrgencyKeywords =
    {
        // magyar
        "azonnal", "sürgős", "haladéktalanul", "utolsó figyelmeztetés",
        "24 órán belül", "48 órán belül", "felfüggesztjük", "lezárjuk a fiókját",
        "korlátozás", "letiltjuk",
        // angol
        "urgent", "immediately", "act now", "final notice", "within 24 hours",
        "account suspended", "account will be closed", "verify now",
    };

    private static readonly string[] CredentialKeywords =
    {
        // magyar
        "jelszó", "jelszavát", "bankkártya", "kártyaszám", "pin kód", "pin-kód",
        "azonosító", "adja meg adatait", "erősítse meg adatait", "bejelentkezés",
        "kattintson ide",
        // angol
        "password", "credit card", "card number", "social security", "login",
        "verify your account", "confirm your identity", "click here",
    };

    private static readonly string[] GenericGreetings =
    {
        "kedves ügyfelünk", "tisztelt ügyfél", "kedves felhasználó",
        "dear customer", "dear user", "dear client", "dear sir/madam",
    };

    private static readonly HashSet<string> UrlShorteners = new(StringComparer.OrdinalIgnoreCase)
    {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
        "rebrand.ly", "cutt.ly", "shorturl.at",
    };

    private static readonly HashSet<string> SuspiciousTlds = new(StringComparer.OrdinalIgnoreCase)
    {
        "zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml", "cf",
        "work", "support", "rest", "icu",
    };

    private static readonly HashSet<string> RiskyExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        "exe", "scr", "bat", "cmd", "js", "vbs", "jar", "msi", "ps1", "lnk",
        "iso", "img", "hta", "docm", "xlsm", "pptm",
    };

    /// <summary>Márka és a hivatalos domainjei (a sorrend számít, ezért tömb).</summary>
    private static readonly (string Brand, string[] Official)[] Brands =
    {
        ("paypal", new[] { "paypal.com" }),
        ("microsoft", new[] { "microsoft.com", "outlook.com", "office.com", "live.com" }),
        ("google", new[] { "google.com", "gmail.com" }),
        ("apple", new[] { "apple.com", "icloud.com" }),
        ("amazon", new[] { "amazon.com", "amazon.de" }),
        ("facebook", new[] { "facebook.com" }),
        ("netflix", new[] { "netflix.com" }),
        ("otpbank", new[] { "otpbank.hu" }),
        ("otp", new[] { "otpbank.hu" }),
        ("kh", new[] { "kh.hu" }),
        ("khbank", new[] { "kh.hu" }),
        ("erste", new[] { "erstebank.hu" }),
        ("mkb", new[] { "mkb.hu" }),
        ("revolut", new[] { "revolut.com" }),
        ("posta", new[] { "posta.hu" }),
        ("foxpost", new[] { "foxpost.hu" }),
        ("gls", new[] { "gls-group.eu", "gls-hungary.com" }),
    };

    /// <summary>Szabály azonosító -> (pontérték, magyar leírás).</summary>
    private static readonly Dictionary<string, (int Points, string Description)> Rules = new()
    {
        ["URGENCY_LANGUAGE"] = (10, "Sürgető, nyomásgyakorló megfogalmazás"),
        ["CREDENTIAL_REQUEST"] = (20, "Jelszó vagy személyes adat bekérése"),
        ["GENERIC_GREETING"] = (5, "Személytelen, általános megszólítás"),
        ["SENDER_NAME_MISMATCH"] = (15, "A megjelenített név márkát tartalmaz, de a feladó domainje nem hivatalos"),
        ["REPLY_TO_MISMATCH"] = (10, "A válaszcím domainje eltér a feladóétól"),
        ["LOOKALIKE_DOMAIN"] = (20, "Ismert márkát utánzó (hasonló) domain"),
        ["IP_URL"] = (20, "Link IP-címre mutat domain helyett"),
        ["URL_SHORTENER"] = (10, "Rövidítő szolgáltatás linkje"),
        ["SUSPICIOUS_TLD"] = (10, "Gyanús, gyakran visszaélésre használt domain-végződés"),
        ["PUNYCODE_URL"] = (15, "Punycode (xn--) domain, homográf támadás lehetősége"),
        ["AT_IN_URL"] = (15, "A link @ jelet tartalmaz (megtévesztő felépítés)"),
        ["HTTP_NO_TLS"] = (5, "Titkosítatlan (http) link"),
        ["LINK_TEXT_MISMATCH"] = (20, "A link látható szövege más domaint mutat, mint a valódi cél"),
        ["RISKY_ATTACHMENT"] = (25, "Veszélyes kiterjesztésű melléklet"),
        ["DOUBLE_EXTENSION"] = (20, "Dupla kiterjesztésű melléklet (pl. számla.pdf.exe)"),
        ["AUTH_FAIL"] = (10, "SPF/DKIM/DMARC ellenőrzés sikertelen"),
        ["MANY_LINKS"] = (5, "Szokatlanul sok link az üzenetben"),
    };

    /// <summary>Az authentikációs hibák együtt legfeljebb ennyit érhetnek.</summary>
    private const int AuthFailCap = 20;

    private static readonly string[] AuthFailValues = { "fail", "softfail", "none", "permerror" };

    private static readonly TimeSpan RegexTimeout = TimeSpan.FromSeconds(1);
    private const RegexOptions Ci = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;

    private static readonly Regex UrlRe =
        new("https?://[^\\s<>\"')]+", Ci, RegexTimeout);

    private static readonly Regex AnchorRe =
        new("<a\\s[^>]*href\\s*=\\s*[\"']([^\"']+)[\"'][^>]*>(.*?)</a>",
            Ci | RegexOptions.Singleline, RegexTimeout);

    private static readonly Regex TagRe = new("<[^>]+>", RegexOptions.None, RegexTimeout);

    private static readonly Regex DomainInTextRe =
        new("([a-z0-9-]+(?:\\.[a-z0-9-]+)+)", Ci, RegexTimeout);

    private static readonly Regex EmailRe =
        new("[\\w.+-]+@([\\w-]+(?:\\.[\\w-]+)+)", Ci, RegexTimeout);

    // ---------------------------------------------------------------- segédek

    private readonly record struct UrlInfo(string Host, bool IsIp, bool HasAtInAuthority);

    private static string DomainOfAddress(string? value)
    {
        if (string.IsNullOrEmpty(value)) return "";
        var m = EmailRe.Match(value);
        return m.Success ? m.Groups[1].Value.ToLowerInvariant() : "";
    }

    private static string DisplayName(string? value)
    {
        if (string.IsNullOrEmpty(value) || !value.Contains('<')) return "";
        return value.Split('<')[0].Trim().Trim('"').ToLowerInvariant();
    }

    private static UrlInfo? ParseUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return null;
        if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps) return null;
        if (string.IsNullOrEmpty(uri.Host)) return null;

        var afterScheme = url[(url.IndexOf("://", StringComparison.Ordinal) + 3)..];
        var slash = afterScheme.IndexOf('/');
        var authority = slash >= 0 ? afterScheme[..slash] : afterScheme;

        var isIp = uri.HostNameType is UriHostNameType.IPv4 or UriHostNameType.IPv6;
        // IdnHost: a nem ASCII (unicode) hostot punycode alakban adja vissza.
        return new UrlInfo(uri.IdnHost.ToLowerInvariant(), isIp, authority.Contains('@'));
    }

    /// <summary>Egyszerűsített "regisztrálható domain" (utolsó két címke).</summary>
    private static string Registrable(string domain)
    {
        var parts = domain.Split('.', StringSplitOptions.RemoveEmptyEntries);
        return parts.Length >= 2 ? string.Join('.', parts[^2..]) : domain;
    }

    private static string Deleet(string text)
    {
        var chars = text.ToCharArray();
        for (var i = 0; i < chars.Length; i++)
        {
            chars[i] = chars[i] switch
            {
                '0' => 'o',
                '1' => 'l',
                '3' => 'e',
                '4' => 'a',
                '5' => 's',
                '$' => 's',
                var c => c,
            };
        }
        return new string(chars).Replace("rn", "m", StringComparison.Ordinal);
    }

    private static List<string> FindKeywords(string text, IEnumerable<string> keywords)
    {
        var low = text.ToLowerInvariant();
        return keywords.Where(k => low.Contains(k, StringComparison.Ordinal)).ToList();
    }

    /// <summary>Visszaadja a márkát, ha a domain annak hasonmása, de nem hivatalos.</summary>
    private static string? LookalikeBrand(string domain)
    {
        var reg = Registrable(domain);
        var label = reg.Split('.')[0];
        foreach (var (brand, official) in Brands)
        {
            if (official.Contains(reg) || brand.Length < 4) continue;
            var norm = Deleet(label);
            // pl. paypa1.com, micr0soft.com, paypal-secure.com, microsoft-login.net
            if (norm == brand || norm.Contains(brand, StringComparison.Ordinal)) return brand;
        }
        return null;
    }

    private static string Truncate(string value, int max) =>
        value.Length <= max ? value : value[..max];

    public static List<string> ExtractUrls(string body, IEnumerable<string>? urls = null)
    {
        var found = new List<string>(urls ?? Enumerable.Empty<string>());
        foreach (Match m in AnchorRe.Matches(body))
            found.Add(m.Groups[1].Value.Trim());
        foreach (Match m in UrlRe.Matches(body))
            found.Add(m.Value);

        var seen = new HashSet<string>(StringComparer.Ordinal);
        return found.Where(seen.Add).ToList();
    }

    // ----------------------------------------------------------------- elemzés

    public static AnalysisResult Analyze(EmailInput email)
    {
        ArgumentNullException.ThrowIfNull(email);

        var sender = email.Sender ?? "";
        var replyTo = email.ReplyTo ?? "";
        var subject = email.Subject ?? "";
        var body = email.Body ?? "";
        var attachments = email.Attachments ?? new List<string>();
        var auth = new Dictionary<string, string>();
        foreach (var (key, value) in email.Auth ?? new Dictionary<string, string>())
            auth[key.ToLowerInvariant()] = (value ?? "").ToLowerInvariant();

        var findings = new List<Finding>();

        void Add(string rule, string evidence = "")
        {
            var (points, description) = Rules[rule];
            findings.Add(new Finding(rule, points, description, Truncate(evidence, 200)));
        }

        var text = $"{subject}\n{TagRe.Replace(body, " ")}";

        // --- tartalmi szabályok
        var hits = FindKeywords(text, UrgencyKeywords);
        if (hits.Count > 0) Add("URGENCY_LANGUAGE", string.Join(", ", hits.Take(5)));

        hits = FindKeywords(text, CredentialKeywords);
        if (hits.Count > 0) Add("CREDENTIAL_REQUEST", string.Join(", ", hits.Take(5)));

        hits = FindKeywords(text, GenericGreetings);
        if (hits.Count > 0) Add("GENERIC_GREETING", hits[0]);

        // --- feladó
        var senderDomain = DomainOfAddress(sender);
        var display = DisplayName(sender);
        if (display.Length > 0 && senderDomain.Length > 0)
        {
            foreach (var (brand, official) in Brands)
            {
                if (brand.Length >= 4
                    && display.Contains(brand, StringComparison.Ordinal)
                    && !official.Contains(Registrable(senderDomain)))
                {
                    Add("SENDER_NAME_MISMATCH", $"{display} <{senderDomain}>");
                    break;
                }
            }
        }

        if (senderDomain.Length > 0)
        {
            var brand = LookalikeBrand(senderDomain);
            if (brand is not null) Add("LOOKALIKE_DOMAIN", $"feladó: {senderDomain} (~{brand})");
        }

        var replyDomain = DomainOfAddress(replyTo);
        if (replyDomain.Length > 0 && senderDomain.Length > 0
            && Registrable(replyDomain) != Registrable(senderDomain))
        {
            Add("REPLY_TO_MISMATCH", $"{senderDomain} vs {replyDomain}");
        }

        // --- hitelesítés
        var authFails = new[] { "spf", "dkim", "dmarc" }
            .Where(k => auth.TryGetValue(k, out var v) && AuthFailValues.Contains(v))
            .ToList();
        if (authFails.Count > 0)
        {
            var points = Math.Min(Rules["AUTH_FAIL"].Points * authFails.Count, AuthFailCap);
            findings.Add(new Finding("AUTH_FAIL", points, Rules["AUTH_FAIL"].Description,
                string.Join(", ", authFails.Select(f => f.ToUpperInvariant()))));
        }

        // --- linkek
        var urls = ExtractUrls(body, email.Urls);
        var flagged = new HashSet<(string Rule, string Host)>();

        void AddOnce(string rule, string host, string evidence)
        {
            if (flagged.Add((rule, host))) Add(rule, evidence);
        }

        foreach (var url in urls)
        {
            if (ParseUrl(url) is not { } info) continue;
            var host = info.Host;

            if (info.IsIp) AddOnce("IP_URL", host, url);
            if (UrlShorteners.Contains(host)) AddOnce("URL_SHORTENER", host, url);

            var tld = host[(host.LastIndexOf('.') + 1)..];
            if (SuspiciousTlds.Contains(tld)) AddOnce("SUSPICIOUS_TLD", host, url);
            if (host.Contains("xn--", StringComparison.Ordinal)) AddOnce("PUNYCODE_URL", host, url);
            if (info.HasAtInAuthority) AddOnce("AT_IN_URL", host, url);
            if (url.StartsWith("http://", StringComparison.OrdinalIgnoreCase)) AddOnce("HTTP_NO_TLS", host, url);

            var brand = LookalikeBrand(host);
            if (brand is not null) AddOnce("LOOKALIKE_DOMAIN", host, $"link: {host} (~{brand})");
        }

        if (urls.Count > 10) Add("MANY_LINKS", $"{urls.Count} link");

        // látható szöveg vs valódi cél (csak HTML-ben)
        foreach (Match m in AnchorRe.Matches(body))
        {
            if (ParseUrl(m.Groups[1].Value.Trim()) is not { } hrefInfo) continue;
            var visible = TagRe.Replace(m.Groups[2].Value, "");
            var shown = DomainInTextRe.Match(visible);
            if (!shown.Success) continue;

            var shownDomain = shown.Groups[1].Value.ToLowerInvariant();
            if (Registrable(shownDomain) != Registrable(hrefInfo.Host))
                AddOnce("LINK_TEXT_MISMATCH", hrefInfo.Host, $"{shownDomain} -> {hrefInfo.Host}");
        }

        // --- mellékletek
        foreach (var name in attachments)
        {
            var parts = name.ToLowerInvariant().Split('.');
            var ext = parts.Length > 1 ? parts[^1] : "";
            if (parts.Length > 2 && RiskyExtensions.Contains(ext)) Add("DOUBLE_EXTENSION", name);
            else if (RiskyExtensions.Contains(ext)) Add("RISKY_ATTACHMENT", name);
        }

        var score = Math.Min(findings.Sum(f => f.Points), 100);
        var level = score < 30 ? "alacsony" : score < 60 ? "közepes" : "magas";

        return new AnalysisResult(score, level, findings, urls);
    }
}
