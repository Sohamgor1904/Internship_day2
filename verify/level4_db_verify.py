"""
LEVEL 4 VERIFICATION — Database Write Verification
Checks PostgreSQL for alert rows, SHAP storage, and attack type distribution.
Run AFTER docker-compose is up:
    docker-compose -f deploy/docker-compose.yml up -d
    python -X utf8 verify/level4_db_verify.py
"""
import sys, os, json, asyncio
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import settings

print("\n" + "="*60)
print("LEVEL 4 — DATABASE WRITE VERIFICATION")
print("="*60)
print(f"\n  DB URL : {settings.DATABASE_URL}")

# ── Check asyncpg availability ───────────────────────────────
try:
    import asyncpg
except ImportError:
    print("  ❌ asyncpg not installed. Run: pip install asyncpg")
    sys.exit(1)

# ── Queries to run ───────────────────────────────────────────
SQL_RECENT_ALERTS = """
    SELECT id, src_ip, dst_ip, classification, l2_threat_prob, l3_threat_prob, created_at
    FROM threat_alerts
    ORDER BY created_at DESC
    LIMIT 10;
"""

SQL_SHAP_CHECK = """
    SELECT id, classification, explanations
    FROM threat_alerts
    WHERE classification = 'Threat-Sequential-APT'
    LIMIT 5;
"""

SQL_DISTRIBUTION = """
    SELECT classification, COUNT(*) AS count
    FROM threat_alerts
    GROUP BY classification
    ORDER BY count DESC;
"""

SQL_STATS = """
    SELECT total_processed, total_alerts, l1_dropped, l2_alerts, l3_alerts, recorded_at
    FROM pipeline_stats
    ORDER BY recorded_at DESC
    LIMIT 5;
"""

async def run_checks():
    results = {}
    # Strip SQLAlchemy prefix if present
    db_url = settings.DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://")
    # Robust host-fallback: if run on host Windows outside docker network, replace docker-host 'db' with '127.0.0.1'
    if "@db:" in db_url:
        db_url = db_url.replace("@db:", "@127.0.0.1:")
    try:
        conn = await asyncpg.connect(db_url, timeout=10)
        print("  ✅ Connected to PostgreSQL\n")
    except Exception as e:
        print(f"  ❌ Cannot connect to database at {db_url}: {e}")
        print("  Make sure docker-compose is running: docker-compose -f deploy/docker-compose.yml up -d")
        return

    # ── 4A: Recent alerts ────────────────────────────────────
    print("-"*60)
    print("4A — RECENT THREAT ALERTS (last 10)")
    print("-"*60)
    try:
        rows = await conn.fetch(SQL_RECENT_ALERTS)
        print(f"  Total rows returned : {len(rows)}")
        if rows:
            for row in rows:
                print(f"  [{row['created_at'].strftime('%H:%M:%S')}] "
                      f"{row['src_ip']:<15} → {row['dst_ip']:<12} | "
                      f"class={row['classification']:<25} | "
                      f"L2={row['l2_threat_prob']:.2f} L3={row['l3_threat_prob']:.2f}")
            results["alerts_exist"] = True
        else:
            print("  ⚠️  No rows in threat_alerts table — run the simulator or API first")
            results["alerts_exist"] = False
        print(f"  [CHECK] Alert rows exist : {'✅ YES' if results['alerts_exist'] else '⚠️  EMPTY TABLE'}")
    except Exception as e:
        print(f"  ❌ Query error: {e}")
        results["alerts_exist"] = False

    # ── 4B: SHAP data stored correctly ───────────────────────
    print("\n" + "-"*60)
    print("4B — SHAP EXPLANATIONS STORED (Threat-Sequential-APT)")
    print("-"*60)
    try:
        rows = await conn.fetch(SQL_SHAP_CHECK)
        print(f"  APT alert rows : {len(rows)}")
        shap_ok = False
        for row in rows:
            expl = row["explanations"]
            if isinstance(expl, str):
                expl = json.loads(expl)
            print(f"  Row {row['id']} — {len(expl)} SHAP features stored:")
            for e in expl[:3]:
                print(f"    {e.get('feature_name','?'):<20} shap={e.get('shap_value','?')}")
            if expl and all("feature_name" in e and "shap_value" in e for e in expl):
                shap_ok = True
        results["shap_correct"] = shap_ok
        if not rows:
            print("  ℹ️  No APT rows yet — trigger sequential threat via API to populate")
            results["shap_correct"] = None
        print(f"  [CHECK] SHAP format {{feature_name, shap_value}} : {'✅ YES' if shap_ok else ('ℹ️  NO APT ROWS YET' if not rows else '❌ WRONG FORMAT')}")
    except Exception as e:
        print(f"  ❌ Query error: {e}")
        results["shap_correct"] = False

    # ── 4C: Attack type distribution ─────────────────────────
    print("\n" + "-"*60)
    print("4C — ALERT TYPE DISTRIBUTION")
    print("-"*60)
    try:
        rows = await conn.fetch(SQL_DISTRIBUTION)
        print(f"  {'Classification':<30} {'Count':>6}")
        print(f"  {'-'*30} {'-'*6}")
        for row in rows:
            print(f"  {row['classification']:<30} {row['count']:>6}")
        results["distribution_ok"] = len(rows) > 0
        print(f"\n  [CHECK] Multiple attack types logged : {'✅ YES' if len(rows) > 1 else ('ℹ️  ONLY 1 TYPE or EMPTY' if len(rows) <= 1 else '❌')}")
    except Exception as e:
        print(f"  ❌ Query error: {e}")
        results["distribution_ok"] = False

    # ── 4D: Pipeline stats table ─────────────────────────────
    print("\n" + "-"*60)
    print("4D — PIPELINE PROCESSING STATS")
    print("-"*60)
    try:
        rows = await conn.fetch(SQL_STATS)
        print(f"  {'Timestamp':<20} {'Processed':>9} {'Alerts':>7} {'L1_Drop':>8} {'L2_Alrt':>8} {'L3_Alrt':>8}")
        print(f"  {'-'*20} {'-'*9} {'-'*7} {'-'*8} {'-'*8} {'-'*8}")
        for row in rows:
            print(f"  {row['recorded_at'].strftime('%Y-%m-%d %H:%M:%S'):<20} "
                  f"{row['total_processed']:>9} {row['total_alerts']:>7} "
                  f"{row['l1_dropped']:>8} {row['l2_alerts']:>8} {row['l3_alerts']:>8}")
        results["stats_ok"] = len(rows) > 0
        print(f"\n  [CHECK] Stats rows exist : {'✅ YES' if results['stats_ok'] else '⚠️  EMPTY'}")
    except Exception as e:
        print(f"  ❌ Query error: {e}")
        results["stats_ok"] = False

    await conn.close()

    # ── Summary ──────────────────────────────────────────────
    print("\n" + "="*60)
    print("LEVEL 4 TEST SUMMARY")
    print("="*60)
    def fmt(v):
        if v is True:   return "✅ PASS"
        if v is False:  return "❌ FAIL"
        return "ℹ️  SKIP (no data yet)"
    print(f"  4A Alerts written to DB      : {fmt(results.get('alerts_exist'))}")
    print(f"  4B SHAP data stored correctly: {fmt(results.get('shap_correct'))}")
    print(f"  4C Type distribution logged  : {fmt(results.get('distribution_ok'))}")
    print(f"  4D Pipeline stats recorded   : {fmt(results.get('stats_ok'))}")
    note = "\n  ℹ️  If DB is empty, run the simulator first:\n     python -X utf8 -m src.ingestion.simulator"
    print(note)
    print("="*60)

asyncio.run(run_checks())
