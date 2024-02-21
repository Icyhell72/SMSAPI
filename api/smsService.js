const axios = require('axios');

async function getToken() {
  const url = 'https://api.orange.com/oauth/v3/token';
  
  const authorization_header = 'Basic R21KdW5kUmNWQ0tJa0JFd1JhU1lwVHY0NlF5ZUpQaHA6VGNuektoU3JTMjFuTGY4Sw=='

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

    return accessToken; // Return the access token
  } catch (error) {
    console.error('Erreur:', error);
    throw error; // Rethrow the error if needed
  }
}



const sendSMS = async (recipientPhoneNumber, verificationCode)  => {
  const accessToken = await getToken();

  const apiUrl = 'https://api.orange.com/smsmessaging/v1/outbound/tel%3A%2B2160000/requests';

  const headers = {
    Authorization: `Bearer ${accessToken}`,
    'Content-Type': 'application/json',
  };

  const requestBody = {
    outboundSMSMessageRequest: {
      address: `tel:+216${recipientPhoneNumber}`,
        senderAddress: 'tel:+2160000',
      outboundSMSTextMessage: {
        message: `Bienvenue chez Para El Farabi Tunisie. Votre code de vérification de compte est: ${verificationCode}`,
      },
    },
  };

  try {
    const response = await axios.post(apiUrl, requestBody, { headers });
    console.log('SMS sent successfully:', response.data);
  } catch (error) {
    console.error('Error sending SMS:', error);
  }
};

module.exports = sendSMS;
