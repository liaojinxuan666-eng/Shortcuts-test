#!/usr/bin/env python3
"""把社区整理的 iOS URL scheme 数据集，收窄成「系统 App 的深链」并打分分层。

三步，每步都可单独重跑：

  1. 读 `corpus/source/awesome-ios-url-schemes.json`（174 个 App / 1442 条 scheme）
  2. 只留 `com.apple.*` 的系统 App，规范化 + 去重
  3. 按「到达该页之后一步之内的后果」打分，输出：
       - corpus/system-schemes.csv    全量，供人工复核与后续批次
       - IntentProbe/ProbeCorpus.swift 只含 A/B 层，编进 App

**为什么不是「全都拖进来」**：`openURL` 从后台发起一律被拒（v11 已钉死），
所以每测一条「被接受」的 URL 就要人手点一次返回。1000 条 = 1000 次点击，
没人做得完。真正的筛选标准不是「这个 scheme 存不存在」，而是
「这条链接把用户送到的那一页，一步之内能造成多大后果」。

打分维度（可争论，但至少是显式的）：

  impact      到达页面后一步之内的后果（装根证书 / 擦机 / 改密码 = 5）
  privilege   目标进程相对本 App 的权限落差（设置、SpringBoard = 高）
  gating      页面自身有无二次认证（要旧密码、要 Face ID → 扣分）
  evidence    社区数据里该条是否有近期 iOS 的可用记录（无 = 扣分）

  score = impact*3 + privilege*2 + evidence - gating
"""

import csv
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "corpus" / "source" / "awesome-ios-url-schemes.json"
# 上游数据集 942KB，不适合塞进 git。本地没有就现拉——CI 里也能跑。
SRC_URL = ("https://raw.githubusercontent.com/SWHL/awesome-ios-url-schemes"
           "/main/src/data/schemes.json")
OUT_CSV = ROOT / "corpus" / "system-schemes.csv"
OUT_SWIFT = ROOT / "IntentProbe" / "ProbeCorpus.swift"

# ---------------------------------------------------------------- 分层规则
# (正则, 层, impact, privilege, gating, evidence, 一句话理由)
# 正则匹配的是「路由部分」：settings-navigation 去掉 scheme 之后，
# 或者 App-prefs:/prefs: 的 root=&path= 归一化之后。**先匹配先生效**。
RULES = [
    # ---- A 层：到达后一步之内就能改变设备安全状态 ----
    (r"General/About/CERT_TRUST_SETTINGS", "A", 5, 5, 0, 2,
     "根证书信任开关。停在开关上，一次点击就是装 MITM 根证书"),
    (r"General/ManagedConfigurationList/VPN$", "A", 4, 5, 1, 1,
     "已装 VPN 配置列表，能看到描述文件装了什么"),
    (r"General/ManagedConfigurationList", "A", 5, 5, 1, 1,
     "VPN 与设备管理。描述文件安装页，企业配置钓鱼的经典落点"),
    (r"General/Reset$", "A", 5, 5, 1, 1,
     "传输或还原 iPhone。再两步是「抹掉所有内容和设置」"),
    (r"Passcode#CHANGE_PASSCODE", "A", 5, 5, 2, 2,
     "改锁屏密码。有旧密码门槛，但把用户直接送到输入框前"),
    (r"Passcode#PASSCODE_TOGGLE", "A", 5, 5, 2, 2,
     "关闭锁屏密码。同样是旧密码门槛，但入口价值最高"),
    (r"Passcode#WIPE_DEVICE", "A", 4, 5, 1, 2,
     "输错十次抹掉数据。开关本身，无二次确认"),
    (r"General/AUTOFILL", "A", 5, 5, 2, 1,
     "自动填充与密码。通往钥匙串的入口"),
    (r"AppleAccount/PASSWORD_AND_SECURITY", "A", 5, 5, 2, 1,
     "Apple 账户登录与安全。改密码 / 加受信任设备都在这一页"),
    (r"AppleAccount/\?aaaction=accountRecovery", "A", 5, 5, 2, 1,
     "账户恢复联系人。账户接管的经典路径"),
    (r"PrivacyAndSecurity/LOCATION/SYSTEM_SERVICES", "A", 3, 5, 0, 1,
     "定位系统服务。含「重要地点」等无法从别处看到的开关"),
    (r"PrivacyAndSecurity/LOCATION/replace_with_app_bundle_id", "A", 4, 5, 0, 1,
     "按 bundle id 直达**任意 App** 的定位授权页。参数化的，值得单独量"),
    (r"PrivacyAndSecurity/LOCATION$", "A", 4, 5, 0, 2,
     "定位服务总表。能一眼看到哪些 App 有定位"),
    (r"PrivacyAndSecurity/LOCKDOWN_MODE", "A", 4, 5, 1, 1,
     "锁定模式开关。反过来也是「关掉它」的入口"),
    (r"PrivacyAndSecurity/STOLEN_DEVICE_PROTECTION", "A", 4, 5, 1, 1,
     "失窃设备保护。关掉它 = 为改密码扫清障碍"),
    (r"PrivacyAndSecurity/PASSKEYS", "A", 4, 5, 1, 0,
     "通行密钥授权。浏览器凭据面的入口"),
    (r"General/SOFTWARE_UPDATE_LINK", "A", 3, 4, 0, 1,
     "软件更新。降级/升级诱导的落点"),
    (r"Apps/(com\.apple\.[A-Za-z0-9\.]+)$", "A", 3, 4, 0, 1,
     "按 bundle id 直达**任意 App** 的设置页（含其权限项）。参数化"),
    (r"PrivacyAndSecurity/(CONTACTS|PHOTOS|MICROPHONE|CAMERA|LOCAL_NETWORK)$", "A", 3, 5, 0, 2,
     "单权限总表。这一页就是「谁拿了这个权限」的全量答案"),

    # ---- B 层：有价值但一步之内改不了安全状态 ----
    (r"PrivacyAndSecurity/SAFETY_CHECK", "B", 3, 5, 1, 0, "安全检查，可一键重置所有共享"),
    (r"PrivacyAndSecurity/PRIVACY_REPORT", "B", 3, 5, 0, 0, "App 隐私报告，取证向"),
    (r"PrivacyAndSecurity/USER_TRACKING", "B", 2, 5, 0, 1, "跟踪授权总表"),
    (r"PrivacyAndSecurity/BLOCKLIST", "B", 3, 5, 0, 0, "已屏蔽联系人"),
    (r"PrivacyAndSecurity/PAIRED_DEVICES", "B", 3, 5, 0, 0, "已配对设备"),
    (r"PrivacyAndSecurity/", "B", 2, 5, 0, 0, "隐私与安全下的其余子页"),
    (r"ScreenTime/CONTENT_PRIVACY", "B", 4, 4, 2, 1, "屏幕使用时间的内容与隐私限制"),
    (r"ScreenTime/", "B", 3, 4, 2, 1, "屏幕使用时间。家长控制面"),
    (r"^com\.apple\.Settings\.Passcode$", "B", 4, 5, 2, 1, "触控 ID 与密码页根"),
    (r"^com\.apple\.Settings\.(WiFi|Bluetooth|Cellular|PersonalHotspot)$", "B", 2, 4, 0, 1,
     "无线/蓝牙/蜂窝/热点。配对与抓包的准备面"),
    (r"^com\.apple\.Settings\.(General|AppleAccount|Family|iCloud)$", "B", 3, 4, 1, 1,
     "通用/账户/家人共享/iCloud 根页"),
    (r"General/(About|STORAGE_MGMT|INTERNATIONAL|Keyboard|DATE_AND_TIME)", "B", 2, 4, 0, 1,
     "设备信息与本地化。指纹向"),
    (r"^com\.apple\.Settings\.(Accessibility|Siri|Notifications|Focus|Wallet|Display|Sounds|Battery|Camera)", "B", 2, 4, 0, 1,
     "其余系统面板根页"),
    (r"^com\.apple\.Settings$", "B", 2, 4, 0, 2, "设置根页"),

    # ---- 老写法（App-prefs / prefs）：历史上被封过又放开过 ----
    (r"root=Privacy", "A", 4, 5, 0, 1, "老写法的隐私页。跟 settings-navigation 同目标，量它还在不在"),
    (r"root=(General&path=Reset)", "A", 5, 5, 1, 0, "老写法的还原页"),
    (r"root=(TOUCHID_PASSCODE|PASSCODE)", "A", 4, 5, 2, 0, "老写法的密码页"),
    (r"root=(General&path=ManagedConfigurationList)", "A", 5, 5, 1, 0, "老写法的描述文件页"),
    (r"root=(WIFI|Bluetooth|LOCATION_SERVICES|MOBILE_DATA_SETTINGS_ID)", "B", 2, 4, 0, 1,
     "老写法的无线/蓝牙/定位/蜂窝"),
    (r"root=", "C", 1, 4, 0, 0, "老写法其余子页"),
]


def norm_route(url: str) -> str:
    """把一条 URL 归一化成可比较的「路由」。"""
    u = url.strip()
    if u.lower().startswith("settings-navigation://"):
        return u[len("settings-navigation://"):]
    m = re.match(r"(?i)^(app-prefs|prefs|perfs):(.*)$", u)
    if m:
        return m.group(2)
    return u


def classify(route: str):
    for pat, tier, imp, priv, gate, ev, why in RULES:
        if re.search(pat, route, re.I):
            return tier, imp, priv, gate, ev, why
    return "C", 1, 3, 0, 0, "系统 App 深链，但一步之内无安全后果"


# 参数化同族：`Apps/<bundleId>` 和 `PrivacyAndSecurity/LOCATION/<bundleId>` 一共 250+ 条，
# 但它们问的是**同一个问题**（「按 bundle id 直达任意 App 的设置页」行不行），
# 抽 3 条代表就够，剩下 250 条全测一遍只会把点击预算烧光。
FAMILY_CAP = {
    r"^com\.apple\.Settings\.Apps/[^/]+$": 3,
    r"PrivacyAndSecurity/LOCATION/[^/]+$": 1,
}


def collapse_family(rows):
    """同族只留前 N 条，其余降 C 层。"""
    kept = {pat: 0 for pat in FAMILY_CAP}
    for r in rows:
        for pat, cap in FAMILY_CAP.items():
            if re.search(pat, r["route"]):
                if kept[pat] >= cap:
                    r["tier"] = "C"
                    r["why"] = "同族参数化样本，已抽前几条代表，本条不单独测"
                    r["score"] = 1
                else:
                    kept[pat] += 1
                break
    return rows


def slug(route: str) -> str:
    s = route.lower()
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    s = re.sub(r"com-apple-settings-", "", s)
    return s[:60] or "root"


def load_source():
    if SRC.exists():
        return json.loads(SRC.read_text())
    import urllib.request
    print(f"source missing, fetching {SRC_URL}")
    SRC.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(SRC_URL, timeout=60) as r:
        raw = r.read()
    SRC.write_bytes(raw)
    return json.loads(raw)


def main() -> int:
    data = load_source()
    rows, seen = [], set()

    for app in data:
        if not str(app.get("bundleId", "")).startswith("com.apple"):
            continue
        for sc in app.get("schemes", []):
            url = (sc.get("url") or "").strip()
            if not url:
                continue
            route = norm_route(url)
            key = route.lower().rstrip("/")
            if key in seen:
                continue
            seen.add(key)
            tier, imp, priv, gate, ev, why = classify(route)
            rows.append({
                "tier": tier,
                "score": imp * 3 + priv * 2 + ev - gate,
                "app": app.get("app", ""),
                "bundleId": app.get("bundleId", ""),
                "url": url,
                "route": route,
                "action": sc.get("action", ""),
                "capability": sc.get("capability", ""),
                "impact": imp, "privilege": priv, "gating": gate, "evidence": ev,
                "why": why,
                "slug": slug(route),
            })

    rows = collapse_family(rows)
    order = {"A": 0, "B": 1, "C": 2}
    rows.sort(key=lambda r: (order[r["tier"]], -r["score"], r["route"]))

    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with OUT_CSV.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    a = [r for r in rows if r["tier"] == "A"]

    # B 层取 28 条，但**按父页面去重**：ScreenTime/CONTENT_PRIVACY 底下有 40 多条
    # 几乎同义的开关，全测一遍等于用 40 次点击问同一个问题。
    b_all = [r for r in rows if r["tier"] == "B"]
    per_bundle, b = {}, []
    for r in b_all:
        fam = r["route"].split("/")[0].split("#")[0]
        if per_bundle.get(fam, 0) >= 3:
            continue
        per_bundle[fam] = per_bundle.get(fam, 0) + 1
        b.append(r)
        if len(b) >= 28:
            break
    print(f"B 层去重后 {len(b)} 条（原 {len(b_all)} 条，覆盖 {len(per_bundle)} 个顶层面板）")
    print(f"total={len(rows)} A={len(a)} B={len(b)} C={len(rows)-len(a)-len(b)}")

    # ---- 生成 Swift：只编 A + B（B 取前 28 条，够两轮点击） ----
    def swift_rows(items, prefix):
        out = []
        for r in items:
            label = f"{prefix}.{r['slug']}"[:70]
            note = r["why"].replace('"', "'")
            url = r["url"].replace('"', '\\"')
            out.append(
                f'        ("{label}",\n'
                f'         "{url}",\n'
                f'         "{note}"),'
            )
        return "\n".join(out)

    swift = f'''// 本文件由 tools/build_corpus.py 生成，**不要手改**。
//
// 数据来源：corpus/source/awesome-ios-url-schemes.json
//   —— 社区整理（curated-chat-2026-05-12 + 若干 gist），**全部 status=unknown**。
//   也就是说这里每一条都是「有人说它能用」，不是「Apple 说过它能用」。
//   唯一的可信度来自本机实跑：sysapp.open 那几行的 verdict。
//
// 收窄过程见 corpus/system-schemes.csv（全量 {len(rows)} 条，含打分与理由）。
// 编进来的只有 A/B 两层：A={len(a)} 条，B={min(len(b), 28)} 条。
//
// 为什么不全编进来：openURL 从后台一律被拒，每测一条被接受的就要人手点一次返回。
// 全量 {len(rows)} 条 ≈ {len(rows)} 次点击，没人做得完。所以先按「一步之内的后果」排序，
// 把点击预算花在能改设备安全状态的那几十条上。

enum ProbeCorpus {{

    /// A 层：到达那一页之后，一步之内就能改变设备安全状态。
    static let tierA: [(label: String, url: String, note: String)] = [
{swift_rows(a, "A")}
    ]

    /// B 层：有价值，但一步之内改不了安全状态。
    static let tierB: [(label: String, url: String, note: String)] = [
{swift_rows(b[:28], "B")}
    ]

    static var all: [(label: String, url: String, note: String)] {{ tierA + tierB }}
}}
'''
    OUT_SWIFT.write_text(swift, encoding="utf-8")
    print(f"wrote {OUT_CSV.relative_to(ROOT)} and {OUT_SWIFT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
