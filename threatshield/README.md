# ML

## Limitations

- Public datasets are older and mostly English.
- The model uses text features only.
- The report hash checks content integrity; it is not a digital signature.
- There is no live threat intelligence or URL fetching; URL analysis is static only.
- Header forensics and geolocation are implemented. Header checks read the SPF, DKIM and DMARC results as stated in the message; they are not re-checked over DNS.
- Geolocation needs a GeoLite2-City.mmdb file that you download from MaxMind (free account) and point to with GEOLITE_CITY_PATH. Without it, the app shows "GeoIP database not installed" and never invents a location.
- IOC extraction and signed reports are planned future work.
- Sender location cannot be verified behind VPNs, Tor, or relays.