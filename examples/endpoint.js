// Example: Encrypt data
async function encryptData(numbers) {
  const response = await fetch('/api/privacy/encrypt', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(numbers)
  });
  return await response.json();
}

// Example: Compute sum of encrypted arrays
async function computeSum(encryptedArrays) {
  const response = await fetch('/api/privacy/sum', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(encryptedArrays)
  });
  return await response.json();
}