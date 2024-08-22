1. Go to RFI & LFI in bWAPP select a language and modigy the URL so it will access a php page via a php base64 filter - language=php://filter/convert.base64-encode/resource=rlfi.php
2. Intrecept the request using burp and send it to the repeater
3. Decode the base64