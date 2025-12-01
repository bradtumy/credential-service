// client.js
const axios = require('axios');
require('dotenv').config();

class Client {
  constructor({ didServiceURL, resolverServiceURL, issuerURL, verifierURL } = {}) {
    this.didServiceURL = didServiceURL || process.env.DID_SERVICE_URL;
    this.resolverServiceURL = resolverServiceURL || process.env.RESOLVER_SERVICE_URL;
    this.issuerURL = issuerURL || this.didServiceURL || process.env.ISSUER_URL;
    this.verifierURL = verifierURL || this.resolverServiceURL || process.env.VERIFIER_URL;
  }

  // Create a DID
  async createDID(orgID) {
    try {
      const payload = {
        type: 'organization',
        organization_id: orgID,
      };
      const response = await axios.post(`${this.didServiceURL}/dids`, payload);
      return response.data;
    } catch (error) {
      console.error('Error creating DID:', error.response ? error.response.data : error.message);
      throw error;
    }
  }

  // Resolve a DID
  async resolveDID(did) {
    try {
      const response = await axios.get(`${this.resolverServiceURL}/dids/resolver`, {
        params: { did },
      });
      return response.data;
    } catch (error) {
      console.error('Error resolving DID:', error.response ? error.response.data : error.message);
      throw error;
    }
  }

  // Issue a credential
  async issueCredential(credential) {
    try {
      const response = await axios.post(`${this.issuerURL}/v1/credentials/issue`, credential);
      return response.data;
    } catch (error) {
      console.error('Error issuing credential:', error.response ? error.response.data : error.message);
      throw error;
    }
  }

  async issueSdJwtCredential({ subject_did, ttl_seconds, claims }) {
    try {
      const payload = { subject_did, ttl_seconds, claims, format: 'sd-jwt' };
      const response = await axios.post(`${this.issuerURL}/v1/credentials/issue`, payload);
      return response.data; // { credential, disclosures, ... }
    } catch (error) {
      console.error('Error issuing SD-JWT:', error.response ? error.response.data : error.message);
      throw error;
    }
  }

  async verifySdJwtCredential({ credential, disclosures }) {
    try {
      const payload = { credential, format: 'sd-jwt', disclosures };
      const response = await axios.post(`${this.verifierURL}/v1/credentials/verify`, payload);
      return response.data; // { active, issuer, subject, ... }
    } catch (error) {
      console.error('Error verifying SD-JWT:', error.response ? error.response.data : error.message);
      throw error;
    }
  }
}

module.exports = Client;
