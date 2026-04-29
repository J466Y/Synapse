import yaml
import sys
from modules.Darktrace.connector import DarktraceClient


sys.path.append("/opt/Synapse")


def main():
    with open("/opt/Synapse/conf/synapse.conf", "r") as f:
        cfg = yaml.safe_load(f)

    dt_cfg = cfg.get("Darktrace", {})

    client = DarktraceClient(
        host=dt_cfg.get("host"),
        public_token=dt_cfg.get("public_token"),
        private_token=dt_cfg.get("private_token"),
        verify_ssl=dt_cfg.get("cert_verification", False),
    )

    print("Testing Darktrace /modelbreaches connection...")
    try:
        # Fetching 1 breach to inspect format
        res = client.breaches.get(minimal=False, expandenums=True, deviceattop=True)
        if isinstance(res, list) and len(res) > 0:
            breach = res[0]
            print("\n--- Model Info ---")
            print("Keys:", list(breach.keys()))
            print("model:", breach.get("model"))
            print("modelName:", breach.get("modelName"))
            print("model_name (other):", breach.get("model_name"))

            # Check for triggered components
            print("\n--- Triggered Components ---")
            components = breach.get("triggeredComponents", [])
            for c in components:
                filters = c.get("triggeredFilters", [])
                for f in filters:
                    print(
                        f"- Filter Type: {f.get('filterType')}, Value: {f.get('trigger', {}).get('value')}"
                    )
        else:
            print("No breaches found or unexpected response format.")
            print(res)
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
