"""#444 B 步共享夹具:真源类 + 原始数据文件 + rebuild() 建小库。

手法沿旧 test_integration 的 _build_engine_shards(写原始文件,再调真实源
类的 rebuild() 生成正版纪元/ptr LMDB 分片),在其上再加一个资产类源
(danmeuk_tor)和网段行,让夹具里有多源同一地址、资产类证人、保留地址
单元、v4/v6 网段单元。

夹具地址全用全球可路由的真实地址:引擎对保留地址(含文档专用段)
短路判 reserved,判不出 malicious;A 步引擎测试(tests/lookup/
test_scan_units.py)同款取址。

顺序约束(py-lmdb 同进程同路径禁双开,A 步引擎测试同款):
    建库(rebuild 后句柄已关)→ 扫描(scan_units,扫描器自开自关)
    → load_db() → lookup()。
每个测试用自己的 tmp 数据目录,测试间路径不重叠;同一测试内先扫描后
load_db,不反转。
"""
import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))      # scripts/ as namespace pkg portion

# 引擎 backend 路径:默认主检出;可用 IP_RADAR_ENGINE_BACKEND 指到别的
# 检出/工作树(#521 实现期用 .worktrees/arch4-521,让集成测试跑在带
# first_hand_source_count 的新字段上)。
ENGINE_BACKEND = Path(os.environ.get(
    "IP_RADAR_ENGINE_BACKEND", "/home/huxiao/dev/pi-ip-lookup-tool/backend"))
ASOF = 1765000000.0                        # 与本机整轮试跑同一判定时刻

# 全 12 列建表(CLI 先建 5 列再 ALTER 7 列共识列之后的形态;列序同
# scripts/generate_blocklist.py 的 UNITS_DDL + CONSENSUS_COLUMNS)
FULL_UNITS_DDL = """
CREATE TABLE units(
    ip TEXT PRIMARY KEY,
    is_v6 INTEGER NOT NULL,
    is_cidr INTEGER NOT NULL,
    last_seen TEXT,
    first_seen TEXT,
    verdict TEXT, confidence INTEGER, classes TEXT, sources TEXT,
    source_count INTEGER, asn TEXT, country TEXT
)
"""


def create_units(db):
    """按全 12 列契约建 units 表(直接调 scan_units/geo 的测试用)。"""
    db.execute(FULL_UNITS_DDL)
    return db


# dataplane 原始行(ASN|ASname|IP|lastseen|category;single-witness 判定
# 只依赖类别与可靠度,地址取真实全球段):
#   1.2.3.5  —— dataplane + turris 单地址 + danmeuk_tor 指控证人 → sc=3(#521 起
#              source_count = 引擎给的 first_hand_source_count,detail 级指控
#              证人含 suspicious 的 danmeuk_tor)
#   1.2.3.7  —— 仅 dataplane → sc=1
#   5.6.7.9  —— dataplane 单地址,落在 turris 5.6.7.0/24 网段内 → sc=2
#   10.99.99.1 —— 保留地址:单元产出但判定短路成 reserved,不进档
#   2606:4700::1 —— 恶意 v6 单源
DATAPLANE_ROWS = [
    "1513399|TEST AS|1.2.3.5|2026-10-01T00:00:00Z|sshpwauth",
    "1513399|TEST AS|1.2.3.7|2026-10-05T00:00:00Z|sshpwauth",
    "1513399|TEST AS|5.6.7.9|2026-10-02T00:00:00Z|dnsrd",
    "64512|RES AS|10.99.99.1|2026-10-02T00:00:00Z|any",
    "64512|V6 AS|2606:4700::1|2026-10-03T00:00:00Z|telnetlogin",
]
# turris(威胁类,网段行让夹具有 v4/v6 网段单元):
TURRIS_ROWS = [
    "1.2.3.5,smtp",                # 与 dataplane 同址(多源同一地址)
    "5.6.7.0/24,smtp",             # v4 网段单元
    "2a00:1450:4001::/48,telnet",  # v6 网段单元(全球可路由段)
]
# danmeuk_tor(资产类,verdict=suspicious 证人;#521 起它是指控证人:
# suspicious 在指控章 _ACCUSING 里,进 first_hand_source_count):
DANMEUK_ROWS = [
    "1.2.3.5",     # 并入多源同址单元
    "1.2.3.99",    # 只有资产类记录 → 不产单元
]

# 夹具宇宙:7 单元(v4 单地址 4 + v6 单地址 1 + v4 网段 1 + v6 网段 1),
# 恶意 6 行(单 IP 池 4),保留 1 行;1.2.3.99 不产单元
UNIVERSE_TOTAL = 7
MALICIOUS_TOTAL = 6
SINGLE_MALICIOUS_POOL = 4


def build_engine_shards(data_dir: Path) -> list:
    """写三源原始文件并 rebuild;返回源实例(进程内注入 registry 用)。"""
    from ipdb._sources.danmeuk_tor import DanMeUkTorSource
    from ipdb._sources.dataplane import DataplaneSource
    from ipdb._sources.turris_greylist import TurrisGreylistSource

    (data_dir / "dataplane.txt").write_text(
        "\n".join(DATAPLANE_ROWS) + "\n", encoding="utf-8")
    dataplane = DataplaneSource(data_dir)
    dataplane.rebuild()

    (data_dir / "turris_greylist.csv").write_text(
        "Address,Tags\n" + "\n".join(TURRIS_ROWS) + "\n", encoding="utf-8")
    turris = TurrisGreylistSource(data_dir)
    turris.rebuild()

    (data_dir / "danmeuk_tor.txt").write_text(
        "\n".join(DANMEUK_ROWS) + "\n", encoding="utf-8")
    tor = DanMeUkTorSource(data_dir)
    tor.rebuild()

    insts = [dataplane, turris, tor]
    # rebuild 会把写库 env 挂在实例的 _reader/_reader6 上;引用计数即关
    # (py-lmdb 同进程同路径禁双开:扫描器还要开同一纪元目录,顺序约束
    # 同 A 步引擎测试)
    for inst in insts:
        inst._reader = None
        inst._reader6 = None
    return insts


@pytest.fixture
def engine_env(tmp_path, monkeypatch):
    """夹具数据目录 + registry 源集合替换成夹具实例。

    进程内测试(扫描、load_db、lookup)经替换后的 registry 只看到夹具
    三源;子进程测试不经此夹具的 registry 部分(子进程自己按 --data-dir
    发现,没有分片的源静默跳过)。"""
    from ipdb import _registry

    data_dir = tmp_path / "data"
    data_dir.mkdir()
    monkeypatch.setenv("IP_RADAR_DATA_DIR", str(data_dir))
    insts = build_engine_shards(data_dir)
    monkeypatch.setattr(_registry, "_sources", insts)
    _registry._enabled_cache["entry"] = None
    _registry._loaded_cache["entry"] = None
    try:
        yield {"data_dir": data_dir, "insts": insts}
    finally:
        # 缓存键持旧 _sources 强引用,显式清一次,下个测试按新集合重算
        _registry._enabled_cache["entry"] = None
        _registry._loaded_cache["entry"] = None
