#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
riskwatch.py — 风险信息抓取 → 分类分级 → 日报 → 企业微信群 + QQ 邮箱

零第三方依赖，仅需 Python 3.9+ 标准库。本机与 GitHub Actions 通用。

覆盖四类信息：食品安全与产品风险、重大案件与执法查获、监管新规与公告、
香港海关执法动态（重点，单独成章并按案件类型细分）；
另设「蛇口海运 · 保税区专题（货运 / 旅检）」跨源汇聚栏目，把散落在各来源里
与海运货运、旅检、保税区及蛇口 / 前海片区相关的案件与监管动态集中呈现。

用法：
    python riskwatch.py --dry-run              抓取并预览报告，不发送
    python riskwatch.py --once                抓一次并投递（定时任务入口）
    python riskwatch.py --test                测企业微信通道
    python riskwatch.py --mail-test           只测 QQ 邮箱 SMTP
    python riskwatch.py --report-test         只测群文件 + 摘要
    python riskwatch.py --list-sources        列出全部数据源
    python riskwatch.py --offline --dry-run    用本地样本离线自检，不联网

云端环境变量（GitHub Actions 用，全部走 Secrets / Variables，不进仓库）：
    WECOM_WEBHOOK       必填，企业微信「消息推送」Webhook
    QQ_SMTP_USER        必填（要发邮件时），发件 QQ 邮箱完整地址
    QQ_SMTP_CODE        必填（要发邮件时），QQ 邮箱 16 位 SMTP 授权码
    RISK_MAIL_TO        收件人，逗号分隔；也可用仓库 Variable
    LLM_API_KEY         可选，OpenAI 兼容大模型密钥；不填则纯统计版
    LLM_BASE_URL        可选，默认 https://api.deepseek.com/v1
    LLM_MODEL           可选，默认 deepseek-chat
    RISK_STATE_FILE     去重状态路径，云端由 actions/cache 持久化
    RISK_REPORT_DIR     报告输出目录，默认 reports/
    RISK_CHUNK_BYTES    单条群消息分片字节数，默认 3000
    RISK_ALERT          设 1 时全源失败会往群里发告警
    RISK_OFFLINE_DIR    离线样本目录（--offline 时读取）

合规与口径：
  * 不抓取微信公众号正文（微信未开放该能力，逆向/模拟登录违反平台规范）。
    官媒公众号、香港海关公众号的内容改用「同一机构官网栏目页 + 香港政府官方 RSS」
    等同源渠道，零费用、可长期无人值守。
  * 只读取政府/监管机构公开发布的标题、日期、链接与摘要，用于个人/内部查阅。
    报告一律附原文链接，不转载正文，不做二次发布。
  * 所有 URL 在日志中经 safe_url() 脱敏；SMTP 授权码与 Webhook key 不写日志。
  * 时间统一 UTC+8（北京时间），不依赖 runner 系统时区。
  * 每份日报同时产出 Markdown 与 Word .docx（标准库手写 OOXML，云端无需装依赖）。
"""

import argparse
import email.utils
import hashlib
import html as html_lib
import json
import logging
import mimetypes
import os
import re
import smtplib
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timedelta, timezone
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from xml.sax.saxutils import escape as xml_escape

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

BASE_DIR = Path(__file__).resolve().parent
STATE_FILE = Path(os.getenv("RISK_STATE_FILE", str(BASE_DIR / "state.json")))
REPORT_DIR = Path(os.getenv("RISK_REPORT_DIR", str(BASE_DIR / "reports")))
OFFLINE_DIR = Path(os.getenv("RISK_OFFLINE_DIR", str(BASE_DIR / "_fixtures")))
try:
    CHUNK_BYTES = max(500, int(os.getenv("RISK_CHUNK_BYTES", "3000")))
except ValueError:
    CHUNK_BYTES = 3000

LOG = logging.getLogger("riskwatch")
CST = timezone(timedelta(hours=8))
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")


def now_cst():
    return datetime.now(CST)


def safe_url(url):
    """日志脱敏：隐去 webhook key / token / secret，避免密钥写进 CI 日志。"""
    s = str(url)
    s = re.sub(r"((?:key|token|sendkey|access_token|secret|code)=)[^&\s]+",
               r"\1***", s, flags=re.I)
    return s


# ------------------------------------------------------------------ 网络层

def _ssl_contexts():
    """先走正常证书校验；个别政府站证书链不全时降级一次（仅公开只读页面）。"""
    good = ssl.create_default_context()
    loose = ssl.create_default_context()
    loose.check_hostname = False
    loose.verify_mode = ssl.CERT_NONE
    return good, loose


def http_get(url, timeout=12, retries=1, referer=None, max_bytes=4_000_000):
    """GET 文本，带指数退避；返回 str。强制 identity 编码避免手工解 gzip。"""
    headers = {"User-Agent": UA, "Accept-Encoding": "identity",
               "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
    if referer:
        headers["Referer"] = referer
    good, loose = _ssl_contexts()
    last_err = None
    for attempt in range(retries + 1):
        for ctx in (good, loose):
            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    raw = resp.read(max_bytes)
                return raw.decode("utf-8", errors="replace")
            except Exception as exc:  # noqa: BLE001
                last_err = exc
        if attempt < retries:
            throttled = "429" in str(last_err) or "Too Many" in str(last_err)
            time.sleep((3.0 if throttled else 1.2) * (2 ** attempt))
    raise RuntimeError(f"请求失败 {safe_url(url)}: {last_err}")


def request_json(url, payload=None, timeout=12, retries=1, referer=None):
    headers = {"User-Agent": UA, "Accept-Encoding": "identity"}
    if referer:
        headers["Referer"] = referer
    data = None
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json; charset=utf-8"
    good, loose = _ssl_contexts()
    last_err = None
    for attempt in range(retries + 1):
        for ctx in (good, loose):
            try:
                req = urllib.request.Request(url, data=data, headers=headers)
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    return json.loads(resp.read().decode("utf-8", errors="replace"))
            except Exception as exc:  # noqa: BLE001
                last_err = exc
        if attempt < retries:
            time.sleep(1.2 * (2 ** attempt))
    raise RuntimeError(f"请求失败 {safe_url(url)}: {last_err}")


def wecom_post(webhook, payload, timeout=12, retries=1):
    """发企业微信消息；HTTP 200 不代表业务成功，必须判 errcode。"""
    result = request_json(webhook, payload, timeout=timeout, retries=retries)
    if result.get("errcode", 0) != 0:
        raise RuntimeError(f"企业微信返回错误: errcode={result.get('errcode')} "
                           f"errmsg={result.get('errmsg')}")
    return result


# ------------------------------------------------------------------ 数据源

SAMR_API = "https://www.samr.gov.cn/api-gateway/jpaas-publish-server/front/page/build/unit"
SAMR_COMMON = {
    "parseType": "bulidstatic",
    "webId": "29e9522dc89d4e088a953d8cede72f4c",
    "tplSetId": "5c30fb89ae5e48b9aefe3cdf49853830",
    "pageType": "column",
    "tagId": "内容区域",
    "editType": "null",
}

# kind: jpaas | html_table | rss | people_search
# focus=True 表示该源为重点源，单独成章、抓取条数加倍、默认不做相关性过滤
PEOPLE_SEARCH_API = "http://search.people.cn/search-platform/front/search"

SOURCES = {
    "hkc_press": {
        "label": "香港海关 · 新闻公报", "region": "香港", "kind": "html_table",
        "parser": "hkc", "url": "https://www.customs.gov.hk/sc/customs-announcement/press-release/index.html",
        "home": "https://www.customs.gov.hk/sc/customs-announcement/press-release/index.html",
        "fixture": "hkc_press.html", "lookback": 7, "focus": True, "limit": 30,
        "note": "重点源：案件查获、走私、贩毒、冒牌货、未完税烟草等",
    },
    "samr_food": {
        "label": "市场监管总局 · 食品抽检司", "region": "内地", "kind": "jpaas",
        "page_id": "c50b450d9afa44e2a7f83f0c2a0c5ffc",
        "url": "https://www.samr.gov.cn/zw/zfxxgk/fdzdgknr/spcjs/",
        "fixture": "samr_food.json", "lookback": 30, "focus": False, "limit": 20,
        "note": "食品抽检不合格通报、非食用物质名录、补充检验方法",
    },
    "samr_fgs": {
        "label": "市场监管总局 · 法规司", "region": "内地", "kind": "jpaas",
        "page_id": "8395bc4a17d04d118c93e9904b258182",
        "url": "https://www.samr.gov.cn/zw/zfxxgk/fdzdgknr/fgs/",
        "fixture": "samr_fgs.json", "lookback": 30, "focus": False, "limit": 20,
        "note": "规章、规范性文件、新规公告（更新频率较低）",
    },
    "samr_news": {
        "label": "市场监管总局 · 总局要闻", "region": "内地", "kind": "jpaas",
        "page_id": "39cd9de1f309431483ef3008309f39ca",
        "url": "https://www.samr.gov.cn/xw/zj/",
        "fixture": "samr_news.json", "lookback": 7, "focus": False, "limit": 20,
        "note": "专项整治、执法行动、典型案例（需相关性过滤）",
    },
    "cfs_alert": {
        "label": "香港食安中心 · 食物警报", "region": "香港", "kind": "html_table",
        "parser": "cfs_alert", "url": "https://www.cfs.gov.hk/sc_chi/whatsnew/whatsnew_fa/whatsnew_fa.html",
        "home": "https://www.cfs.gov.hk/sc_chi/", "fixture": "cfs_alert.html",
        "lookback": 14, "focus": False, "limit": 15,
        "note": "食物警报 / 致敏物警报，含「停止食用」类高风险提示",
    },
    "cfs_press": {
        "label": "香港食安中心 · 新闻稿", "region": "香港", "kind": "html_table",
        "parser": "cfs_press", "url": "https://www.cfs.gov.hk/sc_chi/press/press.html",
        "home": "https://www.cfs.gov.hk/sc_chi/", "fixture": "cfs_press.html",
        "lookback": 7, "focus": False, "limit": 15,
        "note": "抽检结果、专项监察、联合执法行动",
    },
    "hknews_law": {
        "label": "香港政府新闻网 · 治安", "region": "香港", "kind": "rss",
        "url": "https://www.news.gov.hk/tc/categories/law_order/html/articlelist.rss.xml",
        "fixture": "hknews_law.xml", "lookback": 3, "focus": False, "limit": 20,
        "note": "政府中文新闻，需相关性过滤",
    },
    "hknews_health": {
        "label": "香港政府新闻网 · 健康", "region": "香港", "kind": "rss",
        "url": "https://www.news.gov.hk/tc/categories/health/html/articlelist.rss.xml",
        "fixture": "hknews_health.xml", "lookback": 3, "focus": False, "limit": 20,
        "note": "食物安全、药物、卫生相关政府新闻",
    },
    # ---- 权威央媒与海关系统一手源（2026-11-26 实测可达，见指南第九节） ----
    "customs_home": {
        "label": "海关总署 · 首页要闻", "region": "内地", "kind": "html_table",
        "parser": "customs_home", "url": "http://www.customs.gov.cn/",
        "home": "http://www.customs.gov.cn/", "fixture": "customs_home.html",
        "lookback": 7, "focus": False, "limit": 45,
        "note": "一手权威：署级要闻、口岸动态、缉私与通关改革；文章 URL 自带发布日期",
    },
    "people_search": {
        "label": "人民日报 / 人民网 · 官方检索", "region": "内地", "kind": "people_search",
        "url": PEOPLE_SEARCH_API, "fixture": "people_search.json",
        "keywords": ["走私", "海关查获", "食品安全", "保税区", "旅检", "市场监管"],
        "per_keyword": 8, "lookback": 7, "focus": False, "limit": 48,
        "note": "央媒报道线索：按 6 个业务关键词调用官方检索接口，按发布时间倒序",
    },
    "xinhua_legal": {
        "label": "新华网 · 法治频道", "region": "内地", "kind": "html_table",
        "parser": "xinhua", "url": "http://www.news.cn/legal/",
        "home": "https://www.news.cn/", "fixture": "xinhua_legal.html",
        "lookback": 14, "focus": False, "limit": 25,
        "note": "央媒报道线索：典型案例、专项整治、司法解释；文章 URL 自带 8 位日期",
    },
    "cctv_search": {
        "label": "央视网 · 新闻检索", "region": "内地", "kind": "html_table",
        "parser": "cctv",
        "url": "https://search.cctv.com/search.php?qtext=%E6%B5%B7%E5%85%B3%20%E8%B5%B0%E7%A7%81&type=web&sort=date&page=1",
        "home": "https://search.cctv.com/", "fixture": "cctv_search.html",
        "lookback": 30, "focus": False, "limit": 15,
        "note": "央媒报道线索：按发布时间排序，命中海关 / 走私 / 查获类报道；URL 自带日期",
    },
    # 以下为可选补充源，默认不在 config.cloud.json 的 sources 里；需要时打开。
    "hk_gia": {
        "label": "香港政府新闻公报 RSS（英文）", "region": "香港", "kind": "rss",
        "url": "https://www.info.gov.hk/gia/rss/general_en.xml",
        "fixture": "hk_gia_en.xml", "lookback": 2, "focus": False, "limit": 30,
        "note": "全部门公报，标题为英文；仅作补充线索，默认关闭",
    },
    "gnews_food": {
        "label": "新闻网站聚合（Google News 中文）", "region": "综合", "kind": "rss",
        "url": "https://news.google.com/rss/search?q=%E9%A3%9F%E5%93%81%E5%AE%89%E5%85%A8%20%E6%8A%BD%E6%A3%80%20%E4%B8%8D%E5%90%88%E6%A0%BC&hl=zh-CN&gl=CN&ceid=CN:zh-Hans",
        "fixture": "gnews_food.xml", "lookback": 3, "focus": False, "limit": 20,
        "note": "新闻网站补充，境外节点可用；本机网络常被拦，默认关闭",
    },
}

FOCUS_ID = "hkc_press"


def absolute_url(href, home):
    if not href:
        return ""
    if href.startswith("http://") or href.startswith("https://"):
        return href
    return urllib.parse.urljoin(home, href)


def clean_text(s):
    s = html_lib.unescape(re.sub(r"<[^>]+>", "", s or ""))
    return re.sub(r"\s+", " ", s).strip()


def norm_date(raw):
    """把各种日期格式统一成 YYYY-MM-DD；解析不出来返回空串。"""
    raw = (raw or "").strip()
    m = re.search(r"(\d{4})[-/年](\d{1,2})[-/月](\d{1,2})", raw)
    if m:
        return f"{int(m.group(1)):04d}-{int(m.group(2)):02d}-{int(m.group(3)):02d}"
    m = re.search(r"(\d{1,2})\.(\d{1,2})\.(\d{4})", raw)  # 17.11.2026
    if m:
        return f"{int(m.group(3)):04d}-{int(m.group(2)):02d}-{int(m.group(1)):02d}"
    try:
        return email.utils.parsedate_to_datetime(raw).astimezone(CST).strftime("%Y-%m-%d")
    except Exception:
        return ""


def parse_jpaas(html_text, src):
    """市场监管总局 jpaas 接口返回的 data.html 列表。"""
    links = re.findall(r'<a\s+href="([^"]+)"\s+title="([^"]+)"', html_text)
    dates = re.findall(r'class="nav04Left02_contenttime"[^>]*>\s*([^<]+)', html_text)
    out = []
    for idx, (href, title) in enumerate(links):
        out.append({
            "title": clean_text(title),
            "url": absolute_url(href, "https://www.samr.gov.cn"),
            "date": norm_date(dates[idx]) if idx < len(dates) else "",
            "summary": "",
        })
    return out


def parse_cfs_alert(page, src):
    out = []
    for block in re.split(r'<tr\s+class="datarow"', page)[1:]:
        dm = re.search(r'class="subHeader">\s*([\d.]+)', block)
        am = re.search(r'<a\s+href="([^"]+)"[^>]*>(.*?)</a>', block, re.S)
        cm = re.search(r'class="categoryfield">\s*([^<]+)', block)
        if not am:
            continue
        out.append({
            "title": clean_text(am.group(2)),
            "url": absolute_url(am.group(1), src["home"]),
            "date": norm_date(dm.group(1)) if dm else "",
            "summary": ("警报类别：" + clean_text(cm.group(1))) if cm else "",
        })
    return out


def parse_cfs_press(page, src):
    out = []
    for block in re.split(r"<tr>", page)[1:]:
        dm = re.search(r'class="subHeader">\s*([\d.]+)', block)
        am = re.search(r'<a\s+href="([^"]+)"[^>]*>(.*?)</a>', block, re.S)
        if not am or "/sc_chi/press/" not in am.group(1):
            continue
        out.append({
            "title": clean_text(am.group(2)),
            "url": absolute_url(am.group(1), src["home"]),
            "date": norm_date(dm.group(1)) if dm else "",
            "summary": "",
        })
    return out


def parse_hkc(page, src, max_items=60):
    """香港海关新闻公报：<tr data-recorddate="YYYY/M/D"> + <td>日期</td><td><a>标题</a>。

    该列表页含全部历史公报（5000+ 条、约 1.4 MB），最新条目在前面，
    因此只取前 max_items 条，避免每次运行做无意义的全量解析。
    """
    out = []
    pattern = re.compile(
        r'<tr\s+data-recorddate="([^"]+)">\s*<td>([^<]*)</td>\s*'
        r'<td>\s*<a\s+href="([^"]+)"[^>]*>(.*?)</a>', re.S)
    for match in pattern.finditer(page):
        dm, dtext, href, title = match.groups()
        out.append({
            "title": clean_text(title),
            "url": absolute_url(href, "https://www.customs.gov.hk"),
            "date": norm_date(dm) or norm_date(dtext),
            "summary": "",
        })
        if len(out) >= max_items:
            break
    return out


def parse_rss(xml_text, src):
    out = []
    for block in re.findall(r"<item>(.*?)</item>", xml_text, re.S):
        def pick(tag):
            m = re.search(rf"<{tag}[^>]*>(.*?)</{tag}>", block, re.S)
            if not m:
                return ""
            v = m.group(1)
            cd = re.search(r"<!\[CDATA\[(.*?)\]\]>", v, re.S)
            return (cd.group(1) if cd else v).strip()
        title = clean_text(pick("title"))
        link = clean_text(pick("link")) or clean_text(pick("guid"))
        desc = clean_text(pick("description"))[:220]
        if not title:
            continue
        out.append({
            "title": title,
            "url": link,
            "date": norm_date(pick("pubDate")),
            "summary": desc,
        })
    return out


def _url_date(url):
    """三家央媒 / 海关总署的文章 URL 都内嵌发布日期，比解析页面里的日期稳。"""
    for pattern in (r"/(20\d{2})/(\d{2})/(\d{2})/",       # 央视网 /2026/11/13/
                    r"/(20\d{2})(\d{2})(\d{2})/",          # 新华网 /20261125/
                    r"/(20\d{2})-(\d{2})/(\d{2})/"):       # 海关总署 /2026-11/25/
        m = re.search(pattern, url)
        if m:
            return f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
    return ""


def _dedup_rows(rows):
    """同一篇文章常在栏目页里出现多次（图 + 标题），按 URL 去重。"""
    seen, out = set(), []
    for r in rows:
        key = r["url"].split("?")[0] or r["title"]
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


def parse_customs_home(page, src):
    """海关总署首页：<a href="/customs/YYYY-MM/DD/article_xxx.html">标题</a>。"""
    out = []
    for href, title in re.findall(r'<a[^>]+href="([^"]+)"[^>]*>([^<]{8,140})</a>', page):
        if "article_" not in href:
            continue
        t = clean_text(title)
        if not t:
            continue
        u = absolute_url(href, src["home"])
        out.append({"title": t, "url": u, "date": _url_date(u), "summary": ""})
    return _dedup_rows(out)


def parse_xinhua(page, src):
    """新华网栏目页：只取 URL 含 8 位日期的稿件，自动排除模板里的历史存档链接。"""
    out = []
    pattern = r'<a\s+href=[\'"]([^\'"]*?/20\d{6}/[^\'"]*?\.html?)[\'"][^>]*>(.*?)</a>'
    for href, raw_title in re.findall(pattern, page, re.S):
        t = clean_text(raw_title)
        if len(t) < 6:
            continue
        u = absolute_url(href, src["home"])
        out.append({"title": t, "url": u, "date": _url_date(u), "summary": ""})
    return _dedup_rows(out)


def parse_cctv(page, src):
    """央视网检索结果：真实链接在 <span lanmu1="...">，先去 HTML 注释再取 <a> 标题。"""
    page = re.sub(r"<!--.*?-->", "", page, flags=re.S)
    out = []
    for url, body in re.findall(r'<span lanmu1="(https?://[^"]+)"[^>]*>(.*?)</span>', page, re.S):
        m = re.search(r"<a[^>]*>(.*?)</a>", body, re.S)
        if not m:
            continue
        t = clean_text(m.group(1))
        if len(t) < 6:
            continue
        out.append({"title": t, "url": url, "date": _url_date(url), "summary": ""})
    return _dedup_rows(out)


def parse_people_search(payload, src):
    """人民网官方检索返回：{keyword: {code, data:{records:[...]}}}；也兼容单个返回体。"""
    buckets = ([payload] if isinstance(payload, dict) and "data" in payload
               else list(payload.values()) if isinstance(payload, dict) else [])
    out = []
    for data in buckets:
        for rec in ((data or {}).get("data") or {}).get("records") or []:
            title = clean_text(rec.get("title", ""))  # 去掉检索高亮的 <em>
            url = (rec.get("url") or "").strip()
            if not title or not url:
                continue
            try:
                ts = int(rec.get("displayTime") or rec.get("inputTime") or 0)
                d = datetime.fromtimestamp(ts / 1000, CST).strftime("%Y-%m-%d") if ts else ""
            except (ValueError, OSError, OverflowError):
                d = ""
            out.append({
                "title": title, "url": url, "date": d,
                "summary": clean_text(rec.get("content", ""))[:100],
            })
    return _dedup_rows(out)


def fetch_people_search(src, offline=False):
    """按多个业务关键词轮询人民网检索接口；单词失败不影响其他词，全失败才抛错。"""
    if offline:
        merged = json.loads((OFFLINE_DIR / src["fixture"]).read_text(encoding="utf-8"))
    else:
        merged = {}
        start_ms = int((datetime.now(timezone.utc) -
                        timedelta(days=int(src.get("lookback", 7)))).timestamp() * 1000)
        for kw in src.get("keywords", []):
            payload = {"key": kw, "page": 1, "limit": int(src.get("per_keyword", 8)),
                       "hasTitle": True, "hasContent": False, "isFuzzy": False,
                       "type": 0, "sortType": 0, "startTime": start_ms, "endTime": 0}
            try:
                merged[kw] = request_json(src["url"], payload, timeout=12, retries=1,
                                          referer="http://search.people.cn/")
            except Exception as exc:  # noqa: BLE001
                LOG.warning("人民网检索 [%s] 失败：%s", kw, safe_url(str(exc))[:120])
            time.sleep(0.6)
        if not merged:
            raise RuntimeError("人民网检索全部关键词均失败")
    return parse_people_search(merged, src)


def fetch_source(sid, cfg, offline=False):
    """返回 (items, error)。单源失败不影响其他源。"""
    src = SOURCES[sid]
    try:
        if src["kind"] == "people_search":
            return fetch_people_search(src, offline=offline), None
        if src["kind"] == "jpaas":
            if offline:
                p = OFFLINE_DIR / src["fixture"]
                payload = json.loads(p.read_text(encoding="utf-8"))
            else:
                q = dict(SAMR_COMMON, pageId=src["page_id"])
                url = SAMR_API + "?" + urllib.parse.urlencode(q)
                payload = request_json(url, referer=src["url"], timeout=12, retries=1)
            html_text = (payload.get("data") or {}).get("html", "")
            items = parse_jpaas(html_text, src)
        else:
            if offline:
                page = (OFFLINE_DIR / src["fixture"]).read_text(encoding="utf-8", errors="replace")
            else:
                page = http_get(src["url"], timeout=14, retries=1,
                                referer=src.get("home"),
                                max_bytes=2_000_000 if src["kind"] == "rss" else 4_000_000)
            if src["kind"] == "rss":
                items = parse_rss(page, src)
            else:
                items = {"hkc": parse_hkc, "cfs_alert": parse_cfs_alert,
                         "cfs_press": parse_cfs_press,
                         "customs_home": parse_customs_home, "xinhua": parse_xinhua,
                         "cctv": parse_cctv}[src["parser"]](page, src)
        return items, None
    except Exception as exc:  # noqa: BLE001
        return [], str(exc)


# ------------------------------------------------------------------ 分析层

CAT_FOOD = "食品安全与产品风险"
CAT_CASE = "重大案件与执法查获"
CAT_RULE = "监管新规与公告"
CAT_FOCUS = "香港海关 · 新闻公报（重点）"
CAT_OTHER = "综合风险提示"
CATEGORIES = [CAT_FOCUS, CAT_FOOD, CAT_CASE, CAT_RULE, CAT_OTHER]

# 强相关：命中即 +2；一般相关：+1；噪声：-3
STRONG = [
    "抽检不合格", "不合格", "食物警报", "致敏物警报", "召回", "停止食用", "停止饮用",
    "不要食用", "不要饮用", "超标", "非法添加", "非食用物质", "中毒", "污染", "检出",
    "侦破", "查获", "检获", "捣破", "缉获", "罪成", "判囚", "检控", "起诉", "判刑",
    "走私", "贩毒", "毒品", "冒牌", "侵权", "假货", "洗钱", "清洗黑钱", "濒危物种",
    "查处", "处罚", "专项整治", "执法行动", "打击", "案件", "违例", "违法",
    "公告", "通告", "办法", "条例", "规定", "修订", "新规", "标准", "实施",
    "围标", "瓦解", "刊宪", "法例", "规例", "暂停进口", "含菌量", "大肠菌群",
    "兽药残余", "超出法例上限", "食物安全", "走私冻肉", "专项行动",
    # 货运 / 旅检 / 保税区业务词：让央媒报道与总署要闻也能被正确识别
    "集装箱", "货柜", "舱单", "报关", "夹藏", "伪报", "瞒报", "保税", "旅检",
    "水客", "固体废物", "洋垃圾", "缉私", "跨境电商", "查验", "蛇口", "前海",
]
WEAK = [
    "食品", "食品安全", "药品", "化妆品", "医疗器械", "农产品", "保健食品", "标签",
    "市场监管", "监督管理", "监管", "风险", "警示", "提示", "监测", "抽查", "检查",
    "海关", "执法", "管制", "受管制", "通报", "公布", "发布", "行动", "调查",
    "进口", "出口", "跨境", "消费者", "权益", "质量", "安全",
    "口岸", "港口", "码头", "船舶", "货物", "物流", "旅客", "行李", "携带",
    "免税", "保税区", "综合保税区", "海关总署", "深圳海关", "进出口", "通道",
]
NOISE = [
    "接访", "下访", "调研", "慰问", "党建", "表彰", "颁奖", "典礼", "实习计划",
    "招聘", "招标", "中标", "采购", "公示", "人事", "任免", "会议纪要", "座谈",
    "青年发展", "证书颁发", "运动会", "足球", "文艺", "天气预报", "贺词",
    "野鸽", "餵飼", "联欢", "嘉年华", "摄影比赛", "征文",
]
HIGH = [
    "食物警报", "致敏物警报", "停止食用", "停止饮用", "不要食用", "不要饮用",
    "召回", "不合格", "超标", "中毒", "致死", "死亡", "非法添加", "非食用物质",
    "禁售", "下架", "贩毒", "毒品", "检获", "走私", "罪成", "判囚", "洗钱",
    "清洗黑钱", "濒危物种", "刑事", "拘捕", "逮捕", "检控", "罚则", "强制",
    "含菌量", "大肠菌群", "兽药残余", "暂停进口", "超出法例上限", "围标",
]
MEDIUM = [
    "侦破", "查获", "捣破", "查处", "处罚", "打击", "行动", "执法", "通报",
    "公告", "修订", "生效", "抽检", "监测", "抽查", "警示", "风险", "案件",
    "冒牌", "侵权", "未完税", "受管制", "规定", "办法", "条例", "标准",
    "刊宪", "法例", "规例", "集团", "特遣队", "调查结果", "监察",
]

HKC_TYPES = [
    ("毒品与贩毒", ["贩毒", "毒品", "冰毒", "海洛因", "可卡因", "大麻", "制毒", "怀疑毒品"]),
    ("冒牌货与知识产权", ["冒牌", "侵权", "假货", "伪造", "知识产权", "冒牌物品", "盗版"]),
    ("洗钱与贵金属交易", ["清洗黑钱", "洗钱", "贵金属", "宝石", "现金交易"]),
    ("濒危物种与生态", ["濒危物种", "活龟", "象牙", "野生", "受管制属"]),
    ("食药与受管制物品", ["受管制针剂", "受管制药物", "针剂", "药物", "药剂", "药材",
                          "食品安全", "食品"]),
    ("走私与未完税烟草", ["走私", "未完税", "私烟", "香烟", "雪茄", "冻肉", "进口未完税"]),
    ("其他执法动态", []),
]

# ------------------------------------------------------------------ 蛇口专题
# 结构：(章节小标题, 短标签, 关键词)。短标签会显示在每条的「专题」标记里。
# 一条可同时命中多组：正文按第一命中组归组展示，全部命中维度在标签里列全。
LOCAL_TITLE = "蛇口海运 · 保税区专题（货运 / 旅检）"
LOCAL_GROUPS = [
    ("货运渠道（海运 / 集装箱 / 报关）", "货运", [
        "集装箱", "货柜", "海运", "船运", "船舶", "货轮", "舱单", "报关", "转关",
        "货运", "货物", "夹藏", "藏匿", "伪报", "瞒报", "低报", "冻品", "冻肉",
        "固体废物", "洋垃圾", "侵权货物", "大宗", "散货", "码头", "堆场", "提单",
        "拼箱", "查验", "机检", "h986", "过境", "进出口", "货代", "舱位", "装卸",
        "保税物流", "跨境物流", "物流", "货物申报", "品名", "归类", "税号", "舱底",
        "货运渠道", "水运口岸", "港口", "航运", "船公司", "箱号", "封条",
    ]),
    ("旅检渠道（旅客 / 行李 / 携带物）", "旅检", [
        "旅检", "旅客", "行李", "随身携带", "携带", "水客", "免税", "超额携带",
        "入境", "出境", "通关", "代购", "随身", "携带物", "红色通道", "绿色通道",
        "邮轮", "客轮", "口岸旅检", "出入境", "禁止携带", "限量携带", "旅客通道",
        "人身检查", "行李箱", "背包", "超额", "自用品",
    ]),
    ("保税区与特殊监管区域", "保税区", [
        "保税", "综合保税区", "特殊监管区域", "自贸", "自由贸易", "前海", "账册",
        "加工贸易", "二线", "一线", "区内", "出区", "入区", "保税维修", "保税展示",
        "跨境电商", "保税仓", "监管仓", "出口加工区", "海关监管区", "分拨", "集拼",
        "保税研发", "保税租赁", "区外", "围网", "卡口",
    ]),
    ("蛇口 · 前海 · 深圳西部港区", "蛇口本地", [
        "蛇口", "赤湾", "妈湾", "前海", "深圳西部港区", "招商局港口", "蛇口港",
        "深圳海关", "深圳港", "大铲湾", "盐田", "深圳口岸", "深圳湾", "沙头角",
        "文锦渡", "皇岗", "深圳", "粤港澳大湾区", "南沙",
    ]),
]
LOCAL_NAMES = {short: name for name, short, _ in LOCAL_GROUPS}
LOCAL_SHORTS = [short for _, short, _ in LOCAL_GROUPS]

# 香港政府新闻网 / 部分官媒用繁体，关键词表是简体。这里只做「匹配用」的
# 常见字归一化，显示与链接一律保留原文，不改写来源标题。
_T2S_PAIRS = [
    ("檢", "检"), ("獲", "获"), ("偵", "侦"), ("緝", "缉"), ("販", "贩"),
    ("權", "权"), ("藥", "药"), ("劑", "剂"), ("樣", "样"), ("標", "标"),
    ("凍", "冻"), ("煙", "烟"), ("稅", "税"), ("瀕", "濒"), ("種", "种"),
    ("進", "进"), ("罰", "罚"), ("處", "处"), ("專", "专"), ("項", "项"),
    ("執", "执"), ("動", "动"), ("擊", "击"), ("違", "违"), ("報", "报"),
    ("辦", "办"), ("條", "条"), ("規", "规"), ("訂", "订"), ("實", "实"),
    ("準", "准"), ("測", "测"), ("飲", "饮"), ("訴", "诉"), ("搗", "捣"),
    ("錢", "钱"), ("針", "针"), ("屬", "属"), ("貴", "贵"), ("寶", "宝"),
    ("現", "现"), ("圍", "围"), ("團", "团"), ("監", "监"), ("風", "风"),
    ("險", "险"), ("環", "环"), ("衛", "卫"), ("費", "费"), ("質", "质"),
    ("億", "亿"), ("萬", "万"), ("噸", "吨"), ("黴", "霉"), ("籤", "签"),
    ("觸", "触"), ("贓", "赃"), ("養", "养"), ("營", "营"), ("佈", "布"),
    ("發", "发"), ("錄", "录"), ("廢", "废"), ("導", "导"), ("點", "点"),
    ("對", "对"), ("網", "网"), ("關", "关"), ("聯", "联"), ("會", "会"),
    ("議", "议"), ("舉", "举"), ("憲", "宪"), ("隊", "队"), ("貨", "货"),
    ("偽", "伪"), ("緝", "缉"), ("拘", "拘"), ("擺", "摆"), ("賣", "卖"),
    ("購", "购"), ("銷", "销"), ("產", "产"), ("業", "业"), ("農", "农"),
    ("殘", "残"), ("留", "留"), ("過", "过"), ("量", "量"), ("超", "超"),
    ("驗", "验"), ("檢", "检"), ("細", "细"), ("菌", "菌"), ("污", "污"),
    ("染", "染"), ("添", "添"), ("加", "加"), ("禁", "禁"), ("售", "售"),
    ("架", "架"), ("罪", "罪"), ("囚", "囚"), ("刑", "刑"), ("捕", "捕"),
    ("逮", "逮"), ("破", "破"), ("案", "案"), ("件", "件"), ("警", "警"),
    ("示", "示"), ("風", "风"), ("監", "监"), ("管", "管"), ("署", "署"),
    ("食", "食"), ("品", "品"), ("安", "安"), ("全", "全"), ("抽", "抽"),
    ("查", "查"), ("處", "处"), ("行", "行"), ("動", "动"), ("整", "整"),
    ("治", "治"), ("打", "打"), ("擊", "击"), ("緝", "缉"), ("私", "私"),
]
_T2S_MAP = str.maketrans(dict(_T2S_PAIRS))


def to_simplified(text):
    """仅用于关键词匹配的繁→简粗归一化（不影响展示文本）。"""
    return str(text or "").translate(_T2S_MAP)


def local_tags(item):
    """返回该条命中的蛇口专题维度（短标签列表），顺序与 LOCAL_GROUPS 一致。

    只按标题判定：RSS / 检索摘要常是长篇正文片段，参与匹配会把普通报道误标成货运案件。
    """
    text = to_simplified(item.get("title", ""))
    return [short for _, short, keys in LOCAL_GROUPS if any(k in text for k in keys)]


AMOUNT_RE = re.compile(r"(约?\s*[\d.]+\s*(?:亿|万|千)?\s*(?:元|港元|美元|公斤|千克|吨|公吨|件|批次|支|盒|包))")
ENTITY_RE = re.compile(r"(市场监管总局|国家市场监督管理总局|香港海关|食物安全中心|食安中心|海关总署|"
                       r"国家药监局|公安部|卫生署|消费者委员会|消委会|食环署|食物环境卫生署)")


def relevance_score(title, summary=""):
    # 只用标题打分：RSS 的 description 常是长篇全文摘要，参与评分会引入大量噪声。
    t = to_simplified(title)
    score = 0
    if any(k in t for k in NOISE):
        score -= 3
    score += 2 * sum(1 for k in STRONG if k in t)
    score += 1 * sum(1 for k in WEAK if k in t)
    return score


def risk_level(item):
    text = to_simplified(item["title"])
    if any(k in text for k in HIGH):
        return "高"
    if any(k in text for k in MEDIUM):
        return "中"
    return "低"


def classify(item, sid):
    if sid == FOCUS_ID:
        return CAT_FOCUS
    t = to_simplified(item["title"])
    # 「法例 / 规例 / 刊宪」等也出现在食安抽检结果里，先排除明显的产品风险词
    food_risk = ["不合格", "抽检不合格", "检出", "超标", "警报", "致敏", "停止食用",
                 "停止饮用", "含菌量", "大肠菌群", "兽药残余", "样本", "暂停进口",
                 "超出法例上限", "禽肉", "肉类", "污染", "防腐剂", "标签"]
    if not any(k in t for k in food_risk) and any(
            k in t for k in ["公告", "办法", "条例", "规定", "修订", "新规", "名录", "标准",
                             "规范", "实施", "发布《", "征求意见", "废止", "生效", "刊宪",
                             "法例", "规例", "咨询文件"]):
        return CAT_RULE
    if any(k in t for k in ["食品", "食物", "抽检", "不合格", "警报", "致敏", "超标", "检出",
                            "饮用", "食用", "农产品", "餐饮", "奶粉", "药品", "化妆品",
                            "样本", "含菌量", "大肠菌群", "兽药残余", "防腐剂", "标签",
                            "暂停进口", "禽肉", "肉类", "雪糕", "软雪糕"]):
        return CAT_FOOD
    if any(k in t for k in ["侦破", "查获", "检获", "捣破", "案件", "走私", "冒牌", "贩毒",
                            "查处", "处罚", "执法", "打击", "罪成", "判囚", "洗钱",
                            "围标", "拘", "瓦解", "缉", "拘捕", "检控", "专项行动"]):
        return CAT_CASE
    return CAT_OTHER


def hkc_subtype(title):
    t = to_simplified(title)
    for name, keys in HKC_TYPES:
        if any(k in t for k in keys):
            return name
    return HKC_TYPES[-1][0]


def extract_tags(item):
    text = to_simplified(item["title"] + " " + item.get("summary", ""))
    amounts = AMOUNT_RE.findall(text)[:2]
    entities = list(dict.fromkeys(ENTITY_RE.findall(text)))[:3]
    return amounts, entities


def item_hash(item):
    key = (item.get("url") or "").split("?")[0] or item["title"]
    return hashlib.md5(key.encode("utf-8")).hexdigest()[:16]


def load_state():
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).timestamp()
        return {k: v for k, v in data.items()
                if isinstance(v, (int, float)) and v > cutoff}
    except Exception:
        return {}


def save_state(state):
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")
    except Exception as exc:  # noqa: BLE001
        LOG.error("去重状态写入失败（不影响本次投递）：%s", exc)


def collect(cfg, offline=False, only=None):
    """抓取 + 时间窗 + 相关性过滤 + 分类分级，返回 (items, meta)。"""
    selected = only if only else cfg.get("sources", [])
    if isinstance(selected, str):
        ids = [s.strip() for s in selected.split(",") if s.strip() in SOURCES]
    else:
        ids = [s for s in list(selected) if s in SOURCES]
    if not ids:
        raise RuntimeError("没有启用任何数据源")
    min_score = int(cfg.get("min_score", 2))
    per_source = cfg.get("source_min_score") or {}
    state = load_state()
    now = datetime.now(timezone.utc).timestamp()
    items, meta = [], []
    gap = float(os.getenv("RISK_FETCH_GAP", "1.0"))
    for idx, sid in enumerate(ids):
        src = SOURCES[sid]
        raw, err = fetch_source(sid, cfg, offline=offline)
        lookback = int(src.get("lookback", 7))
        if err:
            LOG.warning("源 [%s] 抓取失败：%s", src["label"], err)
            meta.append({"id": sid, "label": src["label"], "ok": False,
                         "total": 0, "kept": 0, "error": err[:120]})
        else:
            kept = 0
            for it in raw[:int(src.get("limit", 20))]:
                if not it.get("title"):
                    continue
                d = it.get("date", "")
                if d:
                    try:
                        age = (now_cst().date() - datetime.strptime(d, "%Y-%m-%d").date()).days
                        if age > lookback or age < -1:
                            continue
                    except ValueError:
                        pass
                score = relevance_score(it["title"], it.get("summary", ""))
                threshold = int(per_source.get(sid, min_score))
                tags = local_tags(it)
                noisy = any(k in to_simplified(it["title"]) for k in NOISE)
                # 命中蛇口专题的条目保底收录（「货运和旅检的相关案件都放进去」），
                # 但党建 / 慰问 / 招聘等噪声标题即使带地域词也不放行。
                if not src.get("focus") and score < threshold and not (tags and not noisy):
                    continue
                h = item_hash(it)
                rec = {
                    "title": it["title"], "url": it.get("url", ""),
                    "date": d or "日期未标注", "summary": it.get("summary", ""),
                    "source": src["label"], "source_id": sid, "region": src["region"],
                    "score": score, "hash": h,
                    "is_new": h not in state,
                    "level": "", "cat": "", "subtype": "", "local_tags": tags,
                    "amounts": [], "entities": [],
                }
                rec["cat"] = classify(rec, sid)
                rec["level"] = risk_level(rec)
                if sid == FOCUS_ID:
                    rec["subtype"] = hkc_subtype(rec["title"])
                rec["amounts"], rec["entities"] = extract_tags(rec)
                items.append(rec)
                kept += 1
            LOG.info("源 [%s] 抓到 %d 条，时间窗内保留 %d 条", src["label"], len(raw), kept)
            meta.append({"id": sid, "label": src["label"], "ok": True,
                         "total": len(raw), "kept": kept, "error": ""})
        if not offline and idx + 1 < len(ids):
            time.sleep(gap)

    # 跨源同题去重：键含「标题 + 日期」，且只在来自不同数据源时合并。
    # 同一栏目（尤其香港海关）常在不同日期发布同名公报，不能误合并。
    seen, uniq = {}, []
    for it in sorted(items, key=lambda x: (x["level"] != "高", -x["score"], x["source_id"] != FOCUS_ID)):
        k = hashlib.md5((re.sub(r"\s+", "", it["title"]) + "|" + it["date"]).encode("utf-8")).hexdigest()[:16]
        if k in seen and seen[k]["source_id"] != it["source_id"]:
            seen[k]["dup_sources"].append(it["source"])
            continue
        it["dup_sources"] = []
        if k not in seen:
            seen[k] = it
        uniq.append(it)
    uniq.sort(key=lambda x: (CATEGORIES.index(x["cat"]),
                             {"高": 0, "中": 1, "低": 2}[x["level"]],
                             not x["is_new"], x["date"]), reverse=False)
    return uniq, meta


def analyse(items, meta, cfg):
    by_cat = {c: [x for x in items if x["cat"] == c] for c in CATEGORIES}
    focus = by_cat[CAT_FOCUS]
    by_sub = {}
    for it in focus:
        by_sub.setdefault(it["subtype"], []).append(it)
    order = {"高": 0, "中": 1, "低": 2}
    high = sorted([x for x in items if x["level"] == "高"],
                  key=lambda x: (x["is_new"], x["date"]), reverse=True)
    for v in by_cat.values():
        v.sort(key=lambda x: (order[x["level"]], not x["is_new"], x["date"]), reverse=False)
    fresh = [x for x in items if x["is_new"]]
    # 蛇口专题：跨源镜像汇总，条目仍留在原分类里，不搬走。
    local = [x for x in items if x.get("local_tags")]
    local_groups = {short: [] for short in LOCAL_SHORTS}
    for it in local:
        local_groups[it["local_tags"][0]].append(it)
    for g in local_groups.values():
        g.sort(key=lambda x: (order[x["level"]], not x["is_new"], x["date"]), reverse=False)
    local.sort(key=lambda x: (order[x["level"]], not x["is_new"], x["date"]), reverse=False)
    local_counts = {s: len(local_groups[s]) for s in LOCAL_SHORTS}
    return {
        "items": items, "by_cat": by_cat, "focus": focus, "by_sub": by_sub,
        "high": high, "fresh": fresh, "meta": meta,
        "local": local, "local_groups": local_groups, "local_counts": local_counts,
        "ok_sources": sum(1 for m in meta if m["ok"]),
        "total_sources": len(meta),
        "counts": {lv: sum(1 for x in items if x["level"] == lv) for lv in ("高", "中", "低")},
        "regions": {r: sum(1 for x in items if x["region"] == r) for r in ("内地", "香港", "综合")},
        "cfg": cfg,
    }


# ------------------------------------------------------------------ 报告

def _item_line(it, with_link=True):
    flag = "🆕" if it["is_new"] else "·"
    title = it["title"].replace("[", "(").replace("]", ")").replace("\n", " ")
    head = f"[{title}]({it['url']})" if (with_link and it["url"]) else title
    tags = []
    if it["subtype"]:
        tags.append(it["subtype"])
    if it.get("local_tags"):
        tags.append("专题：" + "、".join(it["local_tags"]))
    if it["amounts"]:
        tags.append("数字线索：" + "、".join(it["amounts"]))
    if it["dup_sources"]:
        tags.append("同题来源：" + "、".join(dict.fromkeys(it["dup_sources"])))
    line = f"- **[{it['level']}]** {flag} {head} · {it['source']} · {it['date']}"
    if tags:
        line += "\n  - " + " ｜ ".join(tags)
    return line


def build_report(a, llm_text=None):
    now = now_cst()
    c = a["counts"]
    lines = [
        f"# 风险信息日报 · {now:%Y-%m-%d %H:%M}",
        "",
        f"> 数据来源：**{a['ok_sources']}/{a['total_sources']}** 个源可用 · "
        f"本期收录 **{len(a['items'])}** 条（新增 {len(a['fresh'])} 条） · "
        f"高风险 **{c['高']}** 条 / 中风险 {c['中']} 条 / 低风险 {c['低']} 条",
        f"> 覆盖：内地 {a['regions']['内地']} 条 · 香港 {a['regions']['香港']} 条 · "
        f"综合 {a['regions']['综合']} 条；时间统一为北京时间 UTC+8",
        "",
        "## 一、今日速览",
        "",
        "| 指标 | 数值 |",
        "| --- | --- |",
        f"| 本期收录 | {len(a['items'])} 条 |",
        f"| 本次新增 | {len(a['fresh'])} 条 |",
        f"| 高风险 / 中风险 / 低风险 | {c['高']} / {c['中']} / {c['低']} |",
        f"| 蛇口海运 · 保税区专题（货运 / 旅检） | {len(a['local'])} 条 |",
        f"| └ 货运 / 旅检 / 保税区 / 蛇口本地 | "
        f"{a['local_counts']['货运']} / {a['local_counts']['旅检']} / "
        f"{a['local_counts']['保税区']} / {a['local_counts']['蛇口本地']} 条 |",
        f"| 香港海关新闻公报（重点） | {len(a['focus'])} 条 |",
        f"| 食品安全与产品风险 | {len(a['by_cat'][CAT_FOOD])} 条 |",
        f"| 重大案件与执法查获 | {len(a['by_cat'][CAT_CASE])} 条 |",
        f"| 监管新规与公告 | {len(a['by_cat'][CAT_RULE])} 条 |",
        "",
    ]
    if a["high"]:
        lines += ["**最需要优先看的 3 条**", ""]
        for it in a["high"][:3]:
            lines.append(f"- **[{it['level']}]** {it['title']}（{it['source']} · {it['date']}）")
        lines.append("")
    else:
        lines += ["> 本期没有判定为高风险的新条目。", ""]

    lines += ["## 二、高风险预警", ""]
    if a["high"]:
        lines += [_item_line(it) for it in a["high"]] + [""]
    else:
        lines += ["> 本期无高风险条目。", ""]

    # 三、本单位专属专题：跨源镜像汇总，条目仍保留在各自原分类中
    lines += ["## 三、" + LOCAL_TITLE, "",
              "> 结合蛇口海关**海运口岸 + 前海蛇口自贸片区 / 保税区**的业务特点单设的栏目："
              "把本期各来源里与**货运渠道、旅检渠道、保税区及蛇口 / 深圳西部港区**相关的"
              "案件与监管动态集中汇总，方便一线按渠道查阅。",
              "> 本节为**跨源镜像**（条目仍保留在第四至第八节的原有分类里，不重复计入总数）；"
              "正文按第一命中维度归组，命中的全部维度在每条的「专题」标签里列全。", ""]
    if a["local"]:
        for name, short, _ in LOCAL_GROUPS:
            group = a["local_groups"].get(short, [])
            if not group:
                continue
            lines += [f"### {name}（{len(group)} 条）", ""]
            lines += [_item_line(it) for it in group] + [""]
        lines += [f"> 本期专题共 **{len(a['local'])}** 条："
                  + " · ".join(f"{s} {a['local_counts'][s]}" for s in LOCAL_SHORTS) + " 条", ""]
    else:
        lines += ["> 本期时间窗内没有命中该专题的条目。这不代表无相关业务动态，"
                  "可能是来源未发布、页面改版或时间窗过窄（见第九节来源完整性）。", ""]

    lines += ["## 四、" + CAT_FOCUS, "",
              "> 香港海关官网「新闻公报」为本任务的重点源：按案件类型细分，抓取条数与优先级高于其他源。", ""]
    if a["focus"]:
        for st, _ in HKC_TYPES:
            group = a["by_sub"].get(st, [])
            if not group:
                continue
            lines += [f"### {st}（{len(group)} 条）", ""]
            lines += [_item_line(it) for it in group] + [""]
    else:
        lines += ["> 时间窗内未抓到香港海关新闻公报，或该源暂不可用（见第九节）。", ""]

    for idx, (cat, heading) in enumerate(
            [(CAT_FOOD, "五、食品安全与产品风险"),
             (CAT_CASE, "六、重大案件与执法查获"),
             (CAT_RULE, "七、监管新规与公告"),
             (CAT_OTHER, "八、其他风险提示")], start=5):
        group = a["by_cat"][cat]
        lines += [f"## {heading}", ""]
        if group:
            lines += [_item_line(it) for it in group] + [""]
        elif cat == CAT_CASE:
            lines += ["> 本期无独立归入该类的条目；香港海关案件已单列于**第四节（重点）**，"
                      "货运 / 旅检案件另见**第三节专题**。", ""]
        else:
            lines += ["> 本期无该类条目。", ""]

    lines += ["## 九、来源完整性与口径说明", "",
              "| 数据源 | 状态 | 抓到 | 收录 | 备注 |",
              "| --- | --- | --- | --- | --- |"]
    for m in a["meta"]:
        status = "正常" if m["ok"] else "失败"
        note = m["error"] or SOURCES[m["id"]].get("note", "")
        lines.append(f"| {m['label']} | {status} | {m['total']} | {m['kept']} | {note[:60]} |")
    lines += [
        "",
        "> 口径说明：",
        "> 1. 只采集政府/监管机构与权威媒体**公开发布的标题、日期、链接与摘要**，不转载正文；每条均附原文链接，请以原文为准。",
        "> 2. 人民日报 / 新华网 / 央视网等央媒条目属**报道线索**，不是监管机构的正式通报；同一事件被多源报道时会标注「同题来源」，定性以官方原文为准。",
        "> 3. 风险等级、案件类型、类别与专题维度由关键词规则自动判定，属**辅助线索**而非官方定性，可能存在误判或漏判。",
        "> 4. 「🆕」表示 7 天内首次出现；无标记为已报送过的持续在榜条目。报告保留完整快照，群摘要只突出新增。",
        "> 5. 各源设有时间窗（3–30 天，按更新频率不同），抓不到或超窗的条目不纳入，不代表该机构没有发布。",
        "> 6. 微信公众号正文未纳入：微信未开放该能力，改用同一机构官网与香港政府官方 RSS 等同源渠道。",
        "",
    ]
    if llm_text:
        lines += ["## 十、AI 趋势研判（自动生成，仅供参考）", "", llm_text.strip(), "",
                  "> 以上为大模型依据本期标题生成的观点，未经人工核实，不构成风险结论或合规建议。", ""]
    else:
        lines += ["> 本期为纯统计版（未配置大模型密钥，或模型调用失败自动降级）。", ""]
    lines += ["---", "",
              f"*由 riskwatch 自动生成 · {now:%Y-%m-%d %H:%M}（UTC+8）· 每日 08:30 / 18:00*", ""]
    return "\n".join(lines)


def build_digest(a, file_ok=True, formats=None):
    now = now_cst()
    c = a["counts"]
    lines = [
        f"**风险信息日报 · {now:%m-%d %H:%M}**",
        f"> 本期 {len(a['items'])} 条（新增 {len(a['fresh'])}）· 高风险 **{c['高']}** 条 · "
        f"{a['ok_sources']}/{a['total_sources']} 个源可用",
        f"> 香港海关新闻公报（重点）：**{len(a['focus'])}** 条",
        f"> 蛇口专题（货运/旅检/保税/本地）：**{len(a['local'])}** 条 · "
        f"货运 {a['local_counts']['货运']} · 旅检 {a['local_counts']['旅检']} · "
        f"保税区 {a['local_counts']['保税区']} · 蛇口本地 {a['local_counts']['蛇口本地']}",
    ]
    if a["high"]:
        lines.append(f"> 高风险首位：{a['high'][0]['title'][:38]}")
    else:
        lines.append("> 本期无高风险条目")
    if len(a["fresh"]) == 0:
        lines.append("> 本次无新增条目，报告为在榜信息快照")
    if file_ok:
        lines.append(f"> 完整分析见群文件（{('、'.join(formats) if formats else 'md、docx')}，可直接点开）")
    else:
        lines.append("> 群文件发送失败，核心内容已以消息正文发出")
    return "\n".join(lines)


def build_mail_html(a, llm_text=None):
    now = now_cst()
    c = a["counts"]
    color = {"高": "#c0392b", "中": "#b9770e", "低": "#5d6d7e"}

    def esc(s):
        return html_lib.escape(str(s), quote=True)

    def rows(group, limit=40):
        out = []
        for it in group[:limit]:
            title = esc(it["title"])
            link = (f'<a href="{esc(it["url"])}" style="color:#1d4ed8;text-decoration:none">{title}</a>'
                    if it["url"] else title)
            flag = ' <span style="color:#c0392b;font-size:11px">NEW</span>' if it["is_new"] else ""
            bits = [it["subtype"],
                    ("专题：" + "、".join(it.get("local_tags", []))) if it.get("local_tags") else "",
                    ("数字线索：" + "、".join(it["amounts"])) if it["amounts"] else ""]
            extra = (f'<div style="color:#64748b;font-size:12px;margin-top:2px">'
                     f'{esc(" · ".join(x for x in bits if x))}</div>'
                     if any(bits) else "")
            out.append(
                f'<tr><td style="padding:8px 6px;border-bottom:1px solid #e5e7eb;white-space:nowrap">'
                f'<span style="color:{color[it["level"]]};font-weight:700">[{it["level"]}]</span></td>'
                f'<td style="padding:8px 6px;border-bottom:1px solid #e5e7eb">{link}{flag}{extra}</td>'
                f'<td style="padding:8px 6px;border-bottom:1px solid #e5e7eb;color:#64748b;'
                f'font-size:12px;white-space:nowrap">{esc(it["source"])}<br>{esc(it["date"])}</td></tr>')
        return "".join(out) or ('<tr><td colspan="3" style="padding:12px;color:#64748b">本期无该类条目</td></tr>')

    def section(title, group, note=""):
        return (f'<h2 style="font-size:17px;color:#1f2937;margin:26px 0 8px;'
                f'border-left:4px solid #1d4ed8;padding-left:10px">{esc(title)}'
                f'<span style="font-size:12px;color:#64748b;font-weight:400"> （{len(group)} 条）</span></h2>'
                + (f'<p style="color:#64748b;font-size:12px;margin:0 0 6px">{esc(note)}</p>' if note else "")
                + f'<table style="width:100%;border-collapse:collapse;font-size:14px">{rows(group)}</table>')

    parts = [
        '<div style="font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Microsoft YaHei,sans-serif;'
        'max-width:820px;margin:0 auto;color:#1f2937">',
        f'<h1 style="font-size:22px;margin:0 0 4px">风险信息日报 · {now:%Y-%m-%d %H:%M}</h1>',
        f'<p style="color:#64748b;font-size:13px;margin:0 0 18px">'
        f'{a["ok_sources"]}/{a["total_sources"]} 个源可用 · 本期 {len(a["items"])} 条'
        f'（新增 {len(a["fresh"])}）· 内地 {a["regions"]["内地"]} / 香港 {a["regions"]["香港"]} · UTC+8</p>',
        '<div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:14px;margin-bottom:18px">',
        f'<div style="font-size:15px;margin-bottom:6px">高风险 <b style="color:#c0392b">{c["高"]}</b> 条'
        f' · 中风险 <b style="color:#b9770e">{c["中"]}</b> 条 · 低风险 {c["低"]} 条</div>',
    ]
    if a["high"]:
        parts.append('<div style="font-size:13px;color:#475569">优先关注：' +
                     "；".join(esc(x["title"][:42]) for x in a["high"][:3]) + '</div>')
    parts.append('</div>')
    parts.append(section("高风险预警", a["high"]))
    local_html = ""
    for name, short, _ in LOCAL_GROUPS:
        g = a["local_groups"].get(short, [])
        if g:
            local_html += (f'<h3 style="font-size:14px;color:#334155;margin:14px 0 4px">'
                           f'{esc(name)}（{len(g)}）</h3>'
                           f'<table style="width:100%;border-collapse:collapse;font-size:14px">'
                           f'{rows(g)}</table>')
    parts.append(
        '<h2 style="font-size:17px;color:#1f2937;margin:26px 0 8px;border-left:4px solid #0f766e;'
        f'padding-left:10px">{esc(LOCAL_TITLE)}<span style="font-size:12px;color:#64748b;'
        f'font-weight:400"> （{len(a["local"])} 条）</span></h2>'
        '<p style="color:#64748b;font-size:12px">结合海运口岸与保税区业务特点的跨源镜像汇总，'
        '条目仍保留在下方原有分类中；按货运 / 旅检 / 保税区 / 蛇口本地分组，命中维度见每条标签。</p>'
        + (local_html or '<p style="color:#64748b">本期无命中该专题的条目</p>'))
    sub = ""
    for st, _ in HKC_TYPES:
        g = a["by_sub"].get(st, [])
        if g:
            sub += f'<h3 style="font-size:14px;color:#334155;margin:14px 0 4px">{esc(st)}（{len(g)}）</h3>' \
                   f'<table style="width:100%;border-collapse:collapse;font-size:14px">{rows(g)}</table>'
    parts.append(
        '<h2 style="font-size:17px;color:#1f2937;margin:26px 0 8px;border-left:4px solid #1d4ed8;'
        f'padding-left:10px">香港海关 · 新闻公报（重点）<span style="font-size:12px;color:#64748b;'
        f'font-weight:400"> （{len(a["focus"])} 条）</span></h2>'
        '<p style="color:#64748b;font-size:12px">按案件类型细分；本栏目为任务重点源。</p>'
        + (sub or '<p style="color:#64748b">本期无该类条目</p>'))
    parts.append(section(CAT_FOOD, a["by_cat"][CAT_FOOD]))
    parts.append(section(CAT_CASE, a["by_cat"][CAT_CASE]))
    parts.append(section(CAT_RULE, a["by_cat"][CAT_RULE]))
    if a["by_cat"][CAT_OTHER]:
        parts.append(section(CAT_OTHER, a["by_cat"][CAT_OTHER]))
    if llm_text:
        parts.append('<h2 style="font-size:17px;margin:26px 0 8px">AI 趋势研判</h2>'
                     f'<div style="background:#f8fafc;padding:12px;border-radius:6px;font-size:14px">'
                     f'{esc(llm_text).replace(chr(10), "<br>")}</div>'
                     '<p style="color:#64748b;font-size:12px">自动生成，未经人工核实，不构成结论。</p>')
    parts.append(
        '<h2 style="font-size:15px;margin:26px 0 8px">来源完整性</h2>'
        '<table style="width:100%;border-collapse:collapse;font-size:12px">'
        + "".join(
            f'<tr><td style="padding:5px;border-bottom:1px solid #e5e7eb">{esc(m["label"])}</td>'
            f'<td style="padding:5px;border-bottom:1px solid #e5e7eb">'
            f'{"正常" if m["ok"] else "失败"}</td>'
            f'<td style="padding:5px;border-bottom:1px solid #e5e7eb;color:#64748b">'
            f'{esc(m["error"] or str(m["kept"]) + " 条收录")}</td></tr>' for m in a["meta"])
        + '</table>'
        '<p style="color:#64748b;font-size:12px;line-height:1.7;margin-top:18px">'
        '口径：仅采集政府/监管机构与权威媒体公开发布的标题、日期、链接与摘要，不转载正文，请以原文为准；'
        '人民日报 / 新华网 / 央视网等央媒条目为报道线索而非官方通报，同题多源会标注「同题来源」；'
        '风险等级、案件类型与专题维度由规则自动判定，属辅助线索而非官方定性；🆕 / NEW 为 7 天内首次出现。<br>'
        '微信公众号正文未纳入（平台未开放该能力），改用同一机构官网与香港政府官方 RSS 等同源渠道。'
        '</p>'
        f'<p style="color:#94a3b8;font-size:11px;margin-top:16px">由 riskwatch 自动生成 · '
        f'{now:%Y-%m-%d %H:%M} UTC+8 · 每日 08:30 / 18:00</p></div>')
    return ("<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            "</head><body style=\"margin:0;padding:20px;background:#f1f5f9\">"
            + "".join(parts) + "</body></html>")


def save_report(text, directory=None):
    d = Path(directory or REPORT_DIR)
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"riskwatch-{now_cst():%Y-%m-%d-%H%M}.md"
    path.write_text(text, encoding="utf-8")
    return path


# ------------------------------------------------------------------ Word (.docx)
# docx 是 OPC 包：zip + 若干 XML 部件。标准库手写，云端无需 python-docx / LibreOffice。
_XML_DECL = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
_W_NS = ('xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
         'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"')
_INLINES = re.compile(r"\*\*(.+?)\*\*|`([^`]+)`|\[([^\]]+)\]\((https?://[^)\s]+)\)")


def _xml_text(s):
    s = "".join(ch for ch in str(s)
                if ch in "\t\n\r" or 0x20 <= ord(ch) <= 0xD7FF or 0xE000 <= ord(ch) <= 0xFFFD)
    return xml_escape(s)


def _xml_attr(s):
    return xml_escape(str(s), {'"': "&quot;"})


def _inline_runs(text):
    out, pos = [], 0
    for m in _INLINES.finditer(text):
        if m.start() > pos:
            out.append((text[pos:m.start()], False, False, ""))
        if m.group(1) is not None:
            out.append((m.group(1), True, False, ""))
        elif m.group(2) is not None:
            out.append((m.group(2), False, True, ""))
        else:
            out.append((m.group(3), False, False, m.group(4)))
        pos = m.end()
    if pos < len(text):
        out.append((text[pos:], False, False, ""))
    return out or [("", False, False, "")]


def _run_xml(text, bold=False, code=False):
    rpr = ""
    if bold or code:
        rpr = "<w:rPr>" + ("<w:b/>" if bold else "") + (
            '<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas"/><w:color w:val="B54708"/>' if code else "")
        rpr += "</w:rPr>"
    return f'<w:r>{rpr}<w:t xml:space="preserve">{_xml_text(text)}</w:t></w:r>'


def _paragraph_xml(text, style="", bold=False, links=None):
    ppr = f'<w:pPr><w:pStyle w:val="{style}"/></w:pPr>' if style else ""
    body = ""
    for seg, is_bold, is_code, url in _inline_runs(text):
        if url and links is not None:
            rid = links.setdefault(url, f"rIdLink{len(links) + 1}")
            body += (f'<w:hyperlink r:id="{rid}" w:history="1">'
                     f'<w:r><w:rPr><w:rStyle w:val="Hyperlink"/></w:rPr>'
                     f'<w:t xml:space="preserve">{_xml_text(seg)}</w:t></w:r></w:hyperlink>')
        else:
            body += _run_xml(seg, bold or is_bold, is_code)
    return f"<w:p>{ppr}{body}</w:p>"


def _table_xml(rows, links):
    ncols = max((len(r) for r in rows), default=1)
    width = int(9000 / ncols)
    border = "".join(f'<w:{side} w:val="single" w:sz="4" w:color="D0D5DD"/>'
                     for side in ("top", "left", "bottom", "right", "insideH", "insideV"))
    grid = "".join(f'<w:gridCol w:w="{width}"/>' for _ in range(ncols))
    body = ""
    for ri, row in enumerate(rows):
        cells = ""
        for ci in range(ncols):
            val = row[ci] if ci < len(row) else ""
            fill = '<w:shd w:val="clear" w:fill="EEF2F7"/>' if ri == 0 else ""
            cells += (f'<w:tc><w:tcPr><w:tcW w:w="{width}" w:type="dxa"/>{fill}</w:tcPr>'
                      + _paragraph_xml(val, "TableText", bold=(ri == 0), links=links)
                      + "</w:tc>")
        body += f"<w:tr>{cells}</w:tr>"
    return (f'<w:tbl><w:tblPr><w:tblW w:w="9000" w:type="dxa"/>'
            f'<w:tblBorders>{border}</w:tblBorders></w:tblPr>'
            f'<w:tblGrid>{grid}</w:tblGrid>{body}</w:tbl>')


def _docx_styles():
    return f'''{_XML_DECL}<w:styles {_W_NS}>
<w:docDefaults><w:rPrDefault><w:rPr>
  <w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:eastAsia="微软雅黑" w:cs="Calibri"/>
  <w:sz w:val="21"/><w:szCs w:val="21"/>
</w:rPr></w:rPrDefault>
<w:pPrDefault><w:pPr><w:spacing w:after="100" w:line="300" w:lineRule="auto"/></w:pPr></w:pPrDefault>
</w:docDefaults>
<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style>
<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:qFormat/>
  <w:pPr><w:spacing w:after="280"/></w:pPr><w:rPr><w:b/><w:color w:val="1F2937"/><w:sz w:val="36"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:qFormat/>
  <w:pPr><w:keepNext/><w:spacing w:before="280" w:after="120"/><w:outlineLvl w:val="0"/></w:pPr>
  <w:rPr><w:b/><w:color w:val="1D4ED8"/><w:sz w:val="28"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:qFormat/>
  <w:pPr><w:keepNext/><w:spacing w:before="180" w:after="80"/><w:outlineLvl w:val="1"/></w:pPr>
  <w:rPr><w:b/><w:color w:val="334155"/><w:sz w:val="24"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Quote"><w:name w:val="Quote"/><w:basedOn w:val="Normal"/>
  <w:pPr><w:spacing w:after="60"/><w:ind w:left="360"/></w:pPr>
  <w:rPr><w:color w:val="64748B"/><w:i/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="ListPara"><w:name w:val="List Para"/><w:basedOn w:val="Normal"/>
  <w:pPr><w:spacing w:after="40"/><w:ind w:left="360" w:hanging="180"/></w:pPr></w:style>
<w:style w:type="paragraph" w:styleId="TableText"><w:name w:val="Table Text"/><w:basedOn w:val="Normal"/>
  <w:pPr><w:spacing w:after="0"/></w:pPr><w:rPr><w:sz w:val="19"/></w:rPr></w:style>
<w:style w:type="character" w:styleId="Hyperlink"><w:name w:val="Hyperlink"/>
  <w:rPr><w:color w:val="0563C1"/><w:u w:val="single"/></w:rPr></w:style>
</w:styles>'''


def md_to_docx(md_text, out_path):
    links, body, i = {}, [], 0
    lines = md_text.split("\n")
    while i < len(lines):
        s = lines[i].strip()
        if not s:
            i += 1
            continue
        if s.startswith("|") and s.endswith("|"):
            rows = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                if not all(re.fullmatch(r":?-{2,}:?", c) for c in cells if c):
                    rows.append(cells)
                i += 1
            body.append(_table_xml(rows, links))
            continue
        if s.startswith("### "):
            body.append(_paragraph_xml(s[4:], "Heading2", links=links))
        elif s.startswith("## "):
            body.append(_paragraph_xml(s[3:], "Heading1", links=links))
        elif s.startswith("# "):
            body.append(_paragraph_xml(s[2:], "Title", links=links))
        elif s.startswith("> "):
            body.append(_paragraph_xml(s[2:], "Quote", links=links))
        elif s.startswith("- "):
            body.append(_paragraph_xml("• " + s[2:], "ListPara", links=links))
        elif re.match(r"^\d+\.\s", s):
            body.append(_paragraph_xml(re.sub(r"^\d+\.\s*", "", s), "ListPara", links=links))
        elif len(s) >= 3 and set(s) <= {"-", "_", " "}:
            body.append('<w:p><w:pPr><w:pBdr><w:bottom w:val="single" w:sz="4" '
                        'w:color="D0D5DD"/></w:pBdr></w:pPr></w:p>')
        else:
            body.append(_paragraph_xml(s, links=links))
        i += 1
    document = (f'{_XML_DECL}<w:document {_W_NS}><w:body>{"".join(body)}'
                '<w:sectPr><w:pgSz w:w="11906" w:h="16838"/>'
                '<w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134"/></w:sectPr>'
                '</w:body></w:document>')
    content_types = (f'{_XML_DECL}<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                     '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                     '<Default Extension="xml" ContentType="application/xml"/>'
                     '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
                     '<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
                     '</Types>')
    root_rels = (f'{_XML_DECL}<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                 '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
                 'Target="word/document.xml"/></Relationships>')
    link_rels = "".join(
        f'<Relationship Id="{rid}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" '
        f'Target="{_xml_attr(url)}" TargetMode="External"/>' for url, rid in links.items())
    doc_rels = (f'{_XML_DECL}<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                '<Relationship Id="rIdStyles" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
                f'Target="styles.xml"/>{link_rels}</Relationships>')
    parts = {"[Content_Types].xml": content_types, "_rels/.rels": root_rels,
             "word/document.xml": document, "word/styles.xml": _docx_styles(),
             "word/_rels/document.xml.rels": doc_rels}
    for x in parts.values():
        ET.fromstring(x.encode("utf-8"))
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, x in parts.items():
            zf.writestr(name, x.encode("utf-8"))
    return out


# ------------------------------------------------------------------ 企业微信

def upload_wecom_file(webhook, path):
    key = urllib.parse.parse_qs(urllib.parse.urlparse(webhook).query).get("key", [""])[0]
    if not key:
        raise RuntimeError("Webhook 缺少 key 参数，无法上传文件")
    url = f"https://qyapi.weixin.qq.com/cgi-bin/webhook/upload_media?key={key}&type=file"
    data = Path(path).read_bytes()
    boundary = "----riskwatch" + hashlib.md5(f"{Path(path).name}{len(data)}".encode()).hexdigest()[:16]
    head = (f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="media"; filename="{Path(path).name}"; '
            f'filelength={len(data)}\r\nContent-Type: application/octet-stream\r\n\r\n').encode("utf-8")
    body = head + data + f"\r\n--{boundary}--\r\n".encode("utf-8")
    good, loose = _ssl_contexts()
    last = None
    for ctx in (good, loose):
        try:
            req = urllib.request.Request(url, data=body, headers={
                "User-Agent": UA, "Content-Type": f"multipart/form-data; boundary={boundary}"})
            with urllib.request.urlopen(req, timeout=25, context=ctx) as resp:
                result = json.loads(resp.read().decode("utf-8", errors="replace"))
            break
        except Exception as exc:  # noqa: BLE001
            last = exc
    else:
        raise RuntimeError(f"素材上传失败 {safe_url(url)}: {last}") from None
    if result.get("errcode", 0) != 0:
        raise RuntimeError(f"素材上传返回错误: {result}")
    return result["media_id"]


def split_by_bytes(text, limit):
    parts, buf, size = [], [], 0
    for line in text.split("\n"):
        b = len((line + "\n").encode("utf-8"))
        if b > limit:
            line = line.encode("utf-8")[:limit - 20].decode("utf-8", errors="ignore") + "…"
            b = len((line + "\n").encode("utf-8"))
        if size + b > limit and buf:
            parts.append("\n".join(buf))
            buf, size = [], 0
        buf.append(line)
        size += b
    if buf:
        parts.append("\n".join(buf))
    return parts


def _report_core(text):
    wanted = ("## 一、", "## 二、", "## 三、", "## 四、", "## 九、")
    chunks = re.split(r"(?=^## )", text, flags=re.M)
    core = "\n\n".join(c.strip() for c in chunks if c.startswith(wanted))
    out = []
    for line in core.split("\n"):
        s = line.strip()
        if s.startswith("|") and s.endswith("|"):
            cells = [c.strip() for c in s.strip("|").split("|")]
            if not all(re.fullmatch(r":?-{2,}:?", c) for c in cells if c):
                out.append("- " + " · ".join(c for c in cells if c))
        else:
            out.append(line)
    return "**风险日报 · 群文件未发出，以下为核心内容**\n\n" + "\n".join(out)


def deliver_wecom(cfg, a, text, files):
    """发摘要 + 群文件；失败逐项隔离，全失败时把核心正文分片发到群。"""
    wc = cfg.get("wecom") or {}
    if not wc.get("enabled", True):
        LOG.info("企业微信通道已关闭")
        return {"skipped": True}
    webhook = os.getenv("WECOM_WEBHOOK", "").strip()
    if not webhook:
        LOG.warning("未配置 WECOM_WEBHOOK，跳过企业微信投递")
        return {"skipped": True}
    sent, formats = 0, []
    for p in files:
        try:
            mid = upload_wecom_file(webhook, p)
            wecom_post(webhook, {"msgtype": "file", "file": {"media_id": mid}})
            sent += 1
            formats.append(p.suffix.lstrip("."))
            LOG.info("群文件已发送：%s", p.name)
            time.sleep(3.2)
        except Exception as exc:  # noqa: BLE001
            LOG.error("群文件发送失败 %s：%s", p.name, exc)
    file_ok = sent > 0
    fallback, digest_ok = 0, False
    if not file_ok:
        try:
            for idx, part in enumerate(split_by_bytes(_report_core(text), CHUNK_BYTES)[:4]):
                wecom_post(webhook, {"msgtype": "markdown", "markdown": {"content": part}})
                fallback += 1
                if idx < 3:
                    time.sleep(3.2)
        except Exception as exc:  # noqa: BLE001
            LOG.error("正文兜底失败：%s", exc)
    if wc.get("send_digest", True):
        try:
            time.sleep(3.2)
            wecom_post(webhook, {"msgtype": "markdown",
                                 "markdown": {"content": build_digest(a, file_ok, formats)}})
            digest_ok = True
        except Exception as exc:  # noqa: BLE001
            LOG.error("群摘要发送失败：%s", exc)
    if wc.get("high_risk_at_all") and a["counts"]["高"] > 0:
        try:
            time.sleep(3.2)
            wecom_post(webhook, {"msgtype": "text", "text": {
                "content": f"风险提醒：本期有 {a['counts']['高']} 条高风险信息，请查看上方日报。",
                "mentioned_list": ["@all"]}})
        except Exception as exc:  # noqa: BLE001
            LOG.error("高风险 @all 提醒失败：%s", exc)
    LOG.info("企业微信群发结果：文件 %d/%d / 正文兜底 %d 条 / 摘要 %s",
             sent, len(files), fallback, "成功" if digest_ok else "失败")
    if not file_ok and not digest_ok and not fallback:
        raise RuntimeError("企业微信所有投递方式均失败")
    return {"files": sent, "fallback": fallback, "digest": digest_ok}


# ------------------------------------------------------------------ QQ 邮箱

def send_mail(cfg, a, html_text, files, subject=None):
    mc = cfg.get("mail") or {}
    if not mc.get("enabled", True):
        LOG.info("邮件通道已关闭")
        return {"skipped": True}
    user = os.getenv("QQ_SMTP_USER", "").strip()
    code = os.getenv("QQ_SMTP_CODE", "").strip()
    to_raw = os.getenv("RISK_MAIL_TO", "").strip()
    if not (user and code and to_raw):
        LOG.warning("QQ 邮箱配置不全（需 QQ_SMTP_USER / QQ_SMTP_CODE / RISK_MAIL_TO），跳过邮件")
        return {"skipped": True}
    tos = [x.strip() for x in re.split(r"[,;，；\s]+", to_raw) if x.strip()]
    subject = subject or f"风险信息日报 · {now_cst():%Y-%m-%d %H:%M} · 高风险 {a['counts']['高']} 条"
    msg = MIMEMultipart("mixed")
    msg["From"] = email.utils.formataddr(("风险信息日报", user))
    msg["To"] = ", ".join(tos)
    msg["Subject"] = subject
    msg["Date"] = email.utils.formatdate(localtime=True)
    msg["Message-ID"] = email.utils.make_msgid(domain="qq.com")
    alt = MIMEMultipart("alternative")
    plain = (f"风险信息日报 {now_cst():%Y-%m-%d %H:%M}\n"
             f"本期 {len(a['items'])} 条，新增 {len(a['fresh'])} 条，"
             f"高风险 {a['counts']['高']} 条；香港海关新闻公报 {len(a['focus'])} 条；"
             f"蛇口专题（货运/旅检/保税/本地）{len(a['local'])} 条。\n"
             f"完整内容请查看 HTML 正文或附件。\n")
    alt.attach(MIMEText(plain, "plain", "utf-8"))
    alt.attach(MIMEText(html_text, "html", "utf-8"))
    msg.attach(alt)
    attached = 0
    if mc.get("attach", True):
        for p in files:
            try:
                data = Path(p).read_bytes()
                mime, _ = mimetypes.guess_type(p.name)
                part = MIMEApplication(data, _subtype="octet-stream")
                part.add_header("Content-Disposition", "attachment",
                                filename=("utf-8", "", p.name))
                if mime:
                    part.set_type(mime)
                msg.attach(part)
                attached += 1
            except Exception as exc:  # noqa: BLE001
                LOG.error("附件 %s 加入失败：%s", p.name, exc)
    try:
        host = os.getenv("QQ_SMTP_HOST", "smtp.qq.com").strip()
        try:
            port = int(os.getenv("QQ_SMTP_PORT", "465"))
        except ValueError:
            port = 465
        with smtplib.SMTP_SSL(host, port, timeout=25) as srv:
            srv.login(user, code)
            srv.sendmail(user, tos, msg.as_string())
        LOG.info("QQ 邮箱已发送：收件人 %d 个 / 附件 %d 个（SMTP 授权码未写入日志）",
                 len(tos), attached)
        return {"to": len(tos), "attachments": attached}
    except Exception as exc:  # noqa: BLE001
        # 授权码绝不能出现在异常里，统一脱敏
        detail = str(exc).replace(code, "***")
        LOG.error("QQ 邮箱发送失败：%s", detail[:200])
        raise RuntimeError(f"QQ 邮箱 SMTP 失败：{detail[:200]}") from None


# ------------------------------------------------------------------ 可选 AI 研判

def llm_insight(a):
    key = os.getenv("LLM_API_KEY", "").strip()
    if not key:
        return None
    base = os.getenv("LLM_BASE_URL", "https://api.deepseek.com/v1").rstrip("/")
    model = os.getenv("LLM_MODEL", "deepseek-chat")
    brief = []
    for it in a["items"][:60]:
        brief.append(f"[{it['level']}][{it['cat']}] {it['date']} {it['title']}")
    prompt = ("你是风险信息分析助手。以下是本期抓取到的监管、执法与权威媒体公开信息标题，"
              "请写 250–400 字中文研判：归纳 2–3 个主要趋势、指出值得持续关注的品类或手法、"
              "提示 1–2 个信息盲区。若标题中有体现，请专门点出**货运渠道（海运/集装箱/报关）、"
              "旅检渠道（旅客/行李/携带物）、保税区与蛇口/深圳西部港区**相关的手法与趋势。"
              "只依据给定标题，不要编造数据、案件细节或结论，"
              "不要给投资/法律建议，用「本期信息显示」这类审慎措辞。\n\n"
              + "\n".join(brief))
    try:
        result = request_json(base + "/chat/completions", {
            "model": model, "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.3, "max_tokens": 700,
        }, timeout=40, retries=0)
        return (result.get("choices") or [{}])[0].get("message", {}).get("content", "").strip() or None
    except Exception as exc:  # noqa: BLE001 - 模型失败必须静默降级
        LOG.warning("AI 解读失败，自动降级为纯统计版：%s", safe_url(str(exc))[:160])
        return None


# ------------------------------------------------------------------ 主流程

def alert_all_failed():
    webhook = os.getenv("WECOM_WEBHOOK", "").strip()
    if not webhook or os.getenv("RISK_ALERT", "") != "1":
        return
    try:
        wecom_post(webhook, {"msgtype": "text", "text": {
            "content": f"⚠️ 风险信息抓取告警 · {now_cst():%m-%d %H:%M}：所有数据源均失败，本次未生成日报。请查看 Actions 日志。"}})
    except Exception as exc:  # noqa: BLE001
        LOG.error("告警发送失败：%s", exc)


def run_once(cfg, args):
    items, meta = collect(cfg, offline=args.offline, only=args.sources)
    if not any(m["ok"] for m in meta):
        alert_all_failed()
        raise RuntimeError("所有数据源均抓取失败（网络 / 证书 / 页面改版），本次未生成日报")
    a = analyse(items, meta, cfg)
    LOG.info("抓取完成：%d/%d 个源可用 / %d 条收录 / 新增 %d 条 / 高风险 %d 条 / 蛇口专题 %d 条",
             a["ok_sources"], a["total_sources"], len(items), len(a["fresh"]),
             a["counts"]["高"], len(a["local"]))

    llm_text = llm_insight(a) if (cfg.get("report", {}).get("llm", True) and not args.dry_run) else None
    text = build_report(a, llm_text)
    html_text = build_mail_html(a, llm_text)

    path = save_report(text)
    files = [path]
    LOG.info("日报已生成：%s（%d 字节）", path, len(text.encode("utf-8")))
    if cfg.get("report", {}).get("docx", True):
        try:
            docx = md_to_docx(text, path.with_suffix(".docx"))
            files.append(docx)
            LOG.info("Word 版已生成：%s（%d 字节）", docx.name, docx.stat().st_size)
        except Exception as exc:  # noqa: BLE001
            LOG.error("Word 版生成失败（Markdown 不受影响）：%s", exc)

    if args.dry_run:
        print("\n" + text[:3500] + "\n…（完整内容见 " + str(path) + "）\n")
        LOG.info("预览模式：未发送企业微信与邮件，未写去重状态")
        return 0

    results = {}
    # 邮件失败不影响企业微信，反之亦然；但两者都失败时任务标红
    for name, fn in (("wecom", lambda: deliver_wecom(cfg, a, text, files)),
                     ("mail", lambda: send_mail(cfg, a, html_text, files))):
        try:
            results[name] = {"ok": True, "detail": fn()}
        except Exception as exc:  # noqa: BLE001
            LOG.error("通道 [%s] 投递失败：%s", name, exc)
            results[name] = {"ok": False, "detail": str(exc)[:200]}
    ok = [k for k, v in results.items() if v["ok"] and not v["detail"].get("skipped")]
    LOG.info("投递完成：成功通道 %s", ok or "无")
    if not ok:
        raise RuntimeError("企业微信与 QQ 邮箱均未成功投递")

    state = load_state()
    ts = datetime.now(timezone.utc).timestamp()
    for it in items:
        state[it["hash"]] = ts
    save_state(state)
    LOG.info("去重状态已写入 %s（%d 条）", STATE_FILE, len(state))
    return 0


def report_test(cfg):
    webhook = os.getenv("WECOM_WEBHOOK", "").strip()
    if not webhook:
        LOG.error("未配置 WECOM_WEBHOOK，无法自测")
        return 1
    LOG.info("开始群文件连通性自测（不抓数据、不写状态）")
    d = REPORT_DIR
    d.mkdir(parents=True, exist_ok=True)
    p = d / "riskwatch-connectivity-test.md"
    p.write_text(f"# 群文件连通性测试 · {now_cst():%Y-%m-%d %H:%M}\n\n"
                 "> 看到这个文件，说明「上传素材 → 发 file 消息」链路正常。\n", encoding="utf-8")
    try:
        mid = upload_wecom_file(webhook, p)
        LOG.info("① 素材上传成功，media_id=%s…", str(mid)[:8])
        LOG.info("② file 消息返回：%s", wecom_post(webhook, {"msgtype": "file", "file": {"media_id": mid}}))
        time.sleep(3.2)
        LOG.info("③ 文本消息返回：%s", wecom_post(webhook, {"msgtype": "text", "text": {
            "content": f"风险日报群发链路自测 · {now_cst():%H:%M}（北京时间）"}}))
        LOG.info("自测完成：群里收到一个 .md 文件 + 一条文本即代表通道正常")
        return 0
    except Exception as exc:  # noqa: BLE001
        LOG.error("群发自测失败：%s", exc)
        return 1
    finally:
        try:
            p.unlink(missing_ok=True)
        except Exception:
            pass


def mail_test(cfg):
    a = analyse([], [{"id": "test", "label": "连通性测试", "ok": True,
                      "total": 0, "kept": 0, "error": ""}], cfg)
    try:
        r = send_mail(cfg, a, build_mail_html(a), [], subject=f"风险日报 · 邮箱连通性测试 · {now_cst():%m-%d %H:%M}")
        if r.get("skipped"):
            LOG.error("邮件配置不全，测试未执行")
            return 1
        LOG.info("邮箱自测完成：QQ 邮箱收到测试邮件即代表 SMTP 通道正常")
        return 0
    except Exception as exc:  # noqa: BLE001
        LOG.error("邮箱自测失败：%s", exc)
        return 1


def quick_test(cfg):
    webhook = os.getenv("WECOM_WEBHOOK", "").strip()
    ok = 0
    if webhook:
        try:
            wecom_post(webhook, {"msgtype": "text", "text": {
                "content": f"风险信息日报 · 通道测试 · {now_cst():%Y-%m-%d %H:%M}（北京时间）"}})
            LOG.info("企业微信测试消息发送成功")
            ok += 1
        except Exception as exc:  # noqa: BLE001
            LOG.error("企业微信测试失败：%s", exc)
    else:
        LOG.warning("未配置 WECOM_WEBHOOK")
    return 0 if ok else 1


def load_config(path):
    p = Path(path) if path else BASE_DIR / "config.cloud.json"
    if not p.exists():
        LOG.warning("未找到 %s，使用内置默认配置", p)
        return {"sources": ["hkc_press", "samr_food", "samr_fgs", "samr_news",
                            "cfs_alert", "cfs_press", "hknews_law", "hknews_health",
                            "customs_home", "people_search", "xinhua_legal", "cctv_search"],
                "min_score": 2,
                "source_min_score": {"hknews_law": 1, "hknews_health": 1,
                                     "xinhua_legal": 1, "cctv_search": 1},
                "report": {"enabled": True, "docx": True, "llm": True,
                           "send_file": True, "send_digest": True},
                "wecom": {"enabled": True, "send_digest": True},
                "mail": {"enabled": True, "attach": True}}
    return json.loads(p.read_text(encoding="utf-8"))


def main():
    ap = argparse.ArgumentParser(description="风险信息抓取与日报投递（零第三方依赖）")
    ap.add_argument("--once", action="store_true", help="抓一次并投递（定时任务入口）")
    ap.add_argument("--dry-run", action="store_true", help="抓取并预览，不发送、不写状态")
    ap.add_argument("--test", action="store_true", help="测企业微信通道")
    ap.add_argument("--mail-test", action="store_true", help="只测 QQ 邮箱 SMTP")
    ap.add_argument("--report-test", action="store_true", help="只测群文件与摘要链路")
    ap.add_argument("--list-sources", action="store_true", help="列出全部数据源")
    ap.add_argument("--offline", action="store_true", help="用 _fixtures 本地样本，不联网")
    ap.add_argument("--sources", help="逗号分隔，覆盖配置里的源列表")
    ap.add_argument("--config", help="配置文件路径，默认 config.cloud.json")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(message)s",
                        datefmt="%H:%M:%S")
    if args.list_sources:
        for sid, s in SOURCES.items():
            mark = "★重点" if s.get("focus") else "     "
            print(f"{mark} {sid:<16} {s['label']:<34} {s['kind']:<10} {s['url']}")
        return 0
    cfg = load_config(args.config)
    if args.test:
        return quick_test(cfg)
    if args.mail_test:
        return mail_test(cfg)
    if args.report_test:
        return report_test(cfg)
    return run_once(cfg, args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as exc:  # noqa: BLE001
        LOG.error("运行失败：%s", exc)
        sys.exit(1)
