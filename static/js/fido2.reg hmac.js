function start() {
    fetch('/api/registerhmac/begin', {
      method: 'POST',
    }).then(function(response) {
      if(response.ok) return response.arrayBuffer();
      throw new Error('Error getting registration data!');
    }).then(CBOR.decode).then(function(options) {
      return navigator.credentials.create(options);
    }).then(function(attestation) {
      return fetch('/api/registerhmac/complete', {
        method: 'POST',
        headers: {'Content-Type': 'application/cbor'},
        body: CBOR.encode({
          "attestationObject": new Uint8Array(attestation.response.attestationObject),
          "clientDataJSON": new Uint8Array(attestation.response.clientDataJSON),
        })
      });
    }).then(function(response) {
      var stat = response.ok ? 'successful' : 'unsuccessful';
      alert('Registration ' + stat + ' More details in server log...');
    }, function(reason) {
      alert(reason);
    }).then(function() {
      window.location = '/';
    });
    }