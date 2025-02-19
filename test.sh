echo "starting test"
sleep 4
curl \
    -H Content-Type: application/json \
    -d '{"name": "John Doe", "age": 30, "city": "New York"}' \
    -v \
    --proxy socks5://0.0.0.0:1080 \
    https://httpbin.org/anything
