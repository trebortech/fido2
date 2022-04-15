var currloc = window.location; 
fetch('/api/hmac/begin' + currloc.search, {
  method: 'POST',
}).then(function(response) {
  return response.arrayBuffer();
}).then(function(data) {
  return CBOR.decode(data);
}).then(function(options) {
  navigator.credentials.get(options).then(function(assertion) {
    console.log(assertion);
    fetch('/api/hmac/complete', {
      method: 'POST',
      headers: {'Content-Type': 'application/cbor'},
      body: CBOR.encode({
        "credentialId": new Uint8Array(assertion.rawId),
        "authenticatorData": new Uint8Array(assertion.response.authenticatorData),
        "clientDataJSON": new Uint8Array(assertion.response.clientDataJSON),
        "signature": new Uint8Array(assertion.response.signature),
        "Authenticated secret": new Uint8Array(assertion.response),
      })
    }).then(function() {
      alert('Authentication successful.');
    }).then(function(){
      window.location = '/success';
    });
  }, function(reason) {
    console.log('Failed', reason);
    alert('Those are invalid credentials. Please try again.');
    window.location = '/';
  });
});