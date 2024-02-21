const axios = require('axios');

async function getToken() {
  const url = 'https://api.orange.com/oauth/v3/token';
  const client_id = 'GmJundRcVCKIkBEwRaSYpTv46QyeJPhp'
  const client_secret = 'TcnzKhSrS21nLf8K'
  const Basic = 'Basic R21KdW5kUmNWQ0tJa0JFd1JhU1lwVHY0NlF5ZUpQaHA6VGNuektoU3JTMjFuTGY4Sw=='
  const authorization_header = Basic + btoa(client_id + ":" + client_secret)

  const data = new URLSearchParams();
  data.append('grant_type', 'client_credentials');

  const headers = {
    'Authorization': authorization_header,
    'Content-Type': 'application/x-www-form-urlencoded',
    'Accept': 'application/json',
  };

  try {
    const response = await axios.post(url, data, { headers });

    if (response.status !== 200) {
      throw new Error(`HTTP error! Status: ${response.status}`);
    }

    const accessToken = response.data.access_token;
    console.log('Réponse:', response.data);

    return accessToken; // Return the access token
  } catch (error) {
    console.error('Erreur:', error);
    throw error; // Rethrow the error if needed
  }
}

(async () => {
  try {
    const accessToken = await getToken();
    console.log('Access Token:', accessToken);
  } catch (error) {
    console.error('Error:', error);
  }
})();
