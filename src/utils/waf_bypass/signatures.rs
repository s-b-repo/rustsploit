#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WafVendor {
    Radware,
    Cloudflare,
    Shieldsquare,
    Imperva,
    F5BigIp,
    Akamai,
    AwsWaf,
    ModSecurity,
    Generic,
}

#[derive(Debug, Clone)]
pub struct WafSignature {
    pub vendor: WafVendor,
    pub name: &'static str,
    pub headers: &'static [&'static str],
    pub cookies: &'static [&'static str],
    pub body_patterns: &'static [&'static str],
    pub status_codes: &'static [u16],
}

impl WafSignature {
    pub fn vendor_name(&self) -> &'static str {
        match self.vendor {
            WafVendor::Radware => "Radware",
            WafVendor::Cloudflare => "Cloudflare",
            WafVendor::Shieldsquare => "Shieldsquare",
            WafVendor::Imperva => "Imperva",
            WafVendor::F5BigIp => "F5 BIG-IP",
            WafVendor::Akamai => "Akamai",
            WafVendor::AwsWaf => "AWS WAF",
            WafVendor::ModSecurity => "ModSecurity",
            WafVendor::Generic => "Generic",
        }
    }
}

pub fn known_signatures() -> &'static [WafSignature] {
    &[
        WafSignature {
            vendor: WafVendor::Radware,
            name: "Radware Cloud WAF",
            headers: &["x-radware-", "x-rdwr-", "server: radware"],
            cookies: &["rdwr_", "rrpvid"],
            body_patterns: &["radware", "cloud waf", "request blocked by radware"],
            status_codes: &[403, 406],
        },
        WafSignature {
            vendor: WafVendor::Cloudflare,
            name: "Cloudflare WAF",
            headers: &["cf-ray", "cf-cache-status", "server: cloudflare"],
            cookies: &["__cf_bm", "cf_clearance"],
            body_patterns: &[
                "cf-error",
                "cf-mitigated",
                "cloudflare",
                "attention required",
                "cf-browser-verification",
            ],
            status_codes: &[403, 429, 503],
        },
        WafSignature {
            vendor: WafVendor::Shieldsquare,
            name: "Shieldsquare Bot Detection",
            headers: &["x-shieldsquare"],
            cookies: &["__uzma", "__uzmb", "__uzmc", "__uzmd"],
            body_patterns: &["shieldsquare", "validate.perfdrive.com"],
            status_codes: &[403, 429],
        },
        WafSignature {
            vendor: WafVendor::Imperva,
            name: "Imperva / Incapsula WAF",
            headers: &["x-iinfo", "x-cdn"],
            cookies: &["incap_ses_", "visid_incap_", "reese84"],
            body_patterns: &["incapsula", "imperva", "incap_error"],
            status_codes: &[403, 406],
        },
        WafSignature {
            vendor: WafVendor::F5BigIp,
            name: "F5 BIG-IP ASM",
            headers: &["x-wa-info", "x-asm-", "server: bigip"],
            cookies: &[
                "bigipserver",
                "ts",
                "f5_fullwt",
                "lastmrh_session",
                "mrhsession",
            ],
            body_patterns: &[
                "the requested url was rejected",
                "f5 networks",
                "application security manager",
            ],
            status_codes: &[403, 503],
        },
        WafSignature {
            vendor: WafVendor::Akamai,
            name: "Akamai Kona",
            headers: &["x-akamai-", "server: akamaighost"],
            cookies: &["ak_bmsc", "bm_mi", "bm_sv"],
            body_patterns: &["akamai", "reference #", "access denied"],
            status_codes: &[403, 429],
        },
        WafSignature {
            vendor: WafVendor::AwsWaf,
            name: "AWS WAF",
            headers: &["x-amzn-requestid", "x-amz-cf-id", "server: cloudfront"],
            cookies: &["awsalb", "awsalbcors"],
            body_patterns: &["aws waf"],
            status_codes: &[403, 405],
        },
        WafSignature {
            vendor: WafVendor::ModSecurity,
            name: "ModSecurity",
            headers: &[],
            cookies: &[],
            body_patterns: &["modsecurity", "mod_security", "not acceptable"],
            status_codes: &[403, 406],
        },
        WafSignature {
            vendor: WafVendor::Generic,
            name: "Unknown WAF",
            headers: &[],
            cookies: &[],
            body_patterns: &["request blocked", "access denied", "waf", "firewall"],
            status_codes: &[403, 406, 429, 503],
        },
    ]
}
