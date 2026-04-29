import yaml

with open("conf/synapse.conf", "r") as f:
    cfg = yaml.safe_load(f)

th = cfg.get("TheHive", {})
print("automation_enabled:", th.get("automation_enabled"))
enrichment = th.get("enrichment", {})
print("cortex_instance:", enrichment.get("cortex_instance"))
for dt in ["ip", "domain", "fqdn", "hash"]:
    dt_cfg = enrichment.get(dt, {})
    analyzers = dt_cfg.get("analyzers", [])
    blacklist = dt_cfg.get("blacklist", [])
    print(f"  {dt}: {len(analyzers)} analyzers, {len(blacklist)} blacklist entries")
print("Config parsed successfully!")
