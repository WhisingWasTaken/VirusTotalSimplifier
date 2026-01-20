const fetch = require('node-fetch');

exports.handler = async function(event, context) {
    if (event.httpMethod === 'OPTIONS') {
        return {
            statusCode: 200,
            headers: {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type',
                'Access-Control-Allow-Methods': 'POST, OPTIONS'
            },
            body: JSON.stringify({ message: 'CORS preflight' })
        };
    }
    if (event.httpMethod !== 'POST') {
        return {
            statusCode: 405,
            headers: { 'Access-Control-Allow-Origin': '*' },
            body: JSON.stringify({ error: 'Method not allowed' })
        };
    }

    try {
        console.log('File upload request received');
        
        const API_KEY = process.env.VIRUSTOTAL_API_KEY;
        if (!API_KEY) {
            console.error('API key missing in environment');
            return {
                statusCode: 500,
                headers: { 'Access-Control-Allow-Origin': '*' },
                body: JSON.stringify({ error: 'Server configuration error: API key missing' })
            };
        }

        let body;
        if (event.isBase64Encoded) {
            body = Buffer.from(event.body, 'base64');
            console.log('Body is base64 encoded, converted to buffer, length:', body.length);
        } else {
            body = event.body;
            console.log('Body is text, length:', body.length);
        }

        const contentType = event.headers['content-type'] || 'application/octet-stream';
        console.log('Content-Type:', contentType);

        console.log('Forwarding to VirusTotal...');
        const vtResponse = await fetch('https://www.virustotal.com/api/v3/files', {
            method: 'POST',
            headers: {
                'x-apikey': API_KEY,
                'accept': 'application/json',
                'content-type': contentType
            },
            body: body
        });

        console.log('VirusTotal response status:', vtResponse.status);
        
        const responseText = await vtResponse.text();
        console.log('Response length:', responseText.length);
        
        let responseData;
        try {
            responseData = JSON.parse(responseText);
        } catch (e) {
            console.error('Failed to parse JSON:', e.message);
            responseData = { 
                error: 'Invalid response format',
                raw: responseText.substring(0, 200)
            };
        }

        return {
            statusCode: vtResponse.status,
            headers: {
                'Access-Control-Allow-Origin': '*',
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(responseData)
        };

    } catch (error) {
        console.error('Function error:', error);
        return {
            statusCode: 500,
            headers: { 'Access-Control-Allow-Origin': '*' },
            body: JSON.stringify({ 
                error: 'Internal server error',
                message: error.message
            })
        };
    }
};