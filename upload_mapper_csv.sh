TOKEN=$(curl -ksu upload:upload https://up.ezzerouali.com/api/v2/user/token | python3 -c 'import json,sys;print(json.load(sys.stdin)["access_token"])')
HOST=$(hostname); IP=$(hostname -I | awk '{print $1}'); FILE="${HOST}_${IP}_network_services.csv"
curl -kf -H "Authorization: Bearer $TOKEN" --data-binary @network_services.csv "https://up.ezzerouali.com/api/v2/user/files/upload?path=$FILE"
