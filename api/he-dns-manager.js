const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);

class HEDNSManager {
    constructor(username, password) {
        this.username = username;
        this.password = password;
        this.cookieFile = '/tmp/he_cookies.txt';
    }

    /**
     * URL encode a string
     */
    urlEncode(str) {
        return encodeURIComponent(str);
    }

    /**
     * Login to HE.net and get zone list
     */
    async login() {
        try {
            const usernameEncoded = this.urlEncode(this.username);
            const passwordEncoded = this.urlEncode(this.password);
            const body = `email=${usernameEncoded}&pass=${passwordEncoded}`;

            const loginCmd = `curl -s 'https://dns.he.net/' \
        --data '${body}' \
        -c ${this.cookieFile}`;

            const { stdout } = await execPromise(loginCmd);

            if (stdout.includes('>Incorrect<')) {
                throw new Error('Unable to login to dns.he.net - incorrect username or password');
            }

            return stdout;
        } catch (error) {
            throw new Error(`HE.net login failed: ${error.message}`);
        }
    }

    /**
     * Get zone ID for a domain (based on acme.sh _find_zone function)
     */
    async getZoneId(domain) {
        try {
            const response = await this.login();

            // Extract zones table
            const tableMatch = response.match(/id="domains_table"[^]*?<\/table>/);
            if (!tableMatch) {
                throw new Error('Could not find domains table');
            }

            // Extract zone IDs and names
            const zoneIdMatches = tableMatch[0].match(/hosted_dns_zoneid=(\d+)/g) || [];
            const zoneNameMatches = tableMatch[0].match(/name="([^"]+)"[^>]*onclick/g) || [];

            const zoneIds = zoneIdMatches.map(m => m.match(/=(\d+)/)[1]);
            const zoneNames = zoneNameMatches.map(m => m.match(/name="([^"]+)"/)[1]);

            if (zoneIds.length === 0 || zoneNames.length === 0) {
                throw new Error('No zones found in HE.net account');
            }

            // Find matching zone (try progressively shorter domain parts)
            const domainParts = domain.split('.');
            for (let i = 0; i < domainParts.length - 1; i++) {
                const attemptedZone = domainParts.slice(i).join('.');
                const zoneIndex = zoneNames.indexOf(attemptedZone);

                if (zoneIndex !== -1) {
                    return zoneIds[zoneIndex];
                }
            }

            throw new Error(`Zone not found for domain: ${domain}`);
        } catch (error) {
            throw new Error(`Failed to get zone ID: ${error.message}`);
        }
    }

    /**
     * Add A record to HE.net DNS (based on acme.sh dns_he_add function)
     * @param {string} subdomain - Full subdomain (e.g., 'api.trtek.net.tr')
     * @param {string} ipAddress - IP address to point to
     * @param {string} baseDomain - Base domain (e.g., 'trtek.net.tr')
     */
    async addARecord(subdomain, ipAddress, baseDomain) {
        try {
            const zoneId = await this.getZoneId(baseDomain);

            const usernameEncoded = this.urlEncode(this.username);
            const passwordEncoded = this.urlEncode(this.password);

            // Build request body (same format as acme.sh)
            const body = `email=${usernameEncoded}&pass=${passwordEncoded}` +
                `&account=` +
                `&menu=edit_zone` +
                `&Type=A` +
                `&hosted_dns_zoneid=${zoneId}` +
                `&hosted_dns_recordid=` +
                `&hosted_dns_editzone=1` +
                `&Priority=` +
                `&Name=${subdomain}` +
                `&Content=${ipAddress}` +
                `&TTL=300` +
                `&hosted_dns_editrecord=Submit`;

            const addCmd = `curl -s 'https://dns.he.net/' \
        -b ${this.cookieFile} \
        --data '${body}'`;

            const { stdout } = await execPromise(addCmd);

            // Check for success or duplicate
            if (stdout.includes('Successfully added') || stdout.includes('record_id')) {
                return {
                    success: true,
                    subdomain,
                    ipAddress,
                    message: `A record added: ${subdomain} -> ${ipAddress}`
                };
            } else if (stdout.includes('duplicate') || stdout.includes('already exists')) {
                // Record exists, try to update it
                return await this.updateARecord(subdomain, ipAddress, baseDomain);
            } else {
                throw new Error('Unexpected response from HE.net');
            }
        } catch (error) {
            throw new Error(`Failed to add A record: ${error.message}`);
        }
    }

    /**
     * Update existing A record
     */
    async updateARecord(subdomain, ipAddress, baseDomain) {
        try {
            const zoneId = await this.getZoneId(baseDomain);

            // Get zone page to find record ID
            const usernameEncoded = this.urlEncode(this.username);
            const passwordEncoded = this.urlEncode(this.password);

            const getPageCmd = `curl -s 'https://dns.he.net/?hosted_dns_zoneid=${zoneId}&menu=edit_zone&hosted_dns_editzone' \
        -b ${this.cookieFile}`;

            const { stdout: zonePage } = await execPromise(getPageCmd);

            // Find record ID for this subdomain
            const recordIdMatch = zonePage.match(new RegExp(`hosted_dns_recordid=(\\d+)[^>]*${subdomain.replace(/\./g, '\\.')}`));

            if (!recordIdMatch) {
                // Record doesn't exist, add it instead
                return await this.addARecord(subdomain, ipAddress, baseDomain);
            }

            const recordId = recordIdMatch[1];

            // Update the record
            const body = `email=${usernameEncoded}&pass=${passwordEncoded}` +
                `&account=` +
                `&menu=edit_zone` +
                `&Type=A` +
                `&hosted_dns_zoneid=${zoneId}` +
                `&hosted_dns_recordid=${recordId}` +
                `&hosted_dns_editzone=1` +
                `&Priority=` +
                `&Name=${subdomain}` +
                `&Content=${ipAddress}` +
                `&TTL=300` +
                `&hosted_dns_editrecord=Submit`;

            const updateCmd = `curl -s 'https://dns.he.net/' \
        -b ${this.cookieFile} \
        --data '${body}'`;

            await execPromise(updateCmd);

            return {
                success: true,
                subdomain,
                ipAddress,
                message: `A record updated: ${subdomain} -> ${ipAddress}`
            };
        } catch (error) {
            throw new Error(`Failed to update A record: ${error.message}`);
        }
    }

    /**
     * Delete A record from HE.net DNS (based on acme.sh dns_he_rm function)
     * @param {string} subdomain - Full subdomain to delete (e.g., 'api.trtek.net.tr')
     * @param {string} baseDomain - Base domain (e.g., 'trtek.net.tr')
     */
    async deleteARecord(subdomain, baseDomain) {
        try {
            const zoneId = await this.getZoneId(baseDomain);

            // Get zone page to find record ID
            const usernameEncoded = this.urlEncode(this.username);
            const passwordEncoded = this.urlEncode(this.password);

            // Get zone edit page (similar to acme.sh)
            const body = `email=${usernameEncoded}&pass=${passwordEncoded}` +
                `&hosted_dns_zoneid=${zoneId}` +
                `&menu=edit_zone` +
                `&hosted_dns_editzone=`;

            const getPageCmd = `curl -s 'https://dns.he.net/' \
        -b ${this.cookieFile} \
        --data '${body}'`;

            const { stdout: zonePage } = await execPromise(getPageCmd);

            // Check if subdomain exists in response
            if (!zonePage.includes(subdomain)) {
                console.log(`Subdomain ${subdomain} not found in zone page`);
                return {
                    success: true,
                    subdomain,
                    message: `A record not found (already deleted): ${subdomain}`
                };
            }

            console.log(`Found ${subdomain} in zone page, parsing HTML...`);

            // Parse HTML to find record ID (similar to acme.sh method)
            // Split by <tr>, find the row containing our subdomain, extract record ID
            const rows = zonePage
                .replace(/#/g, '')
                .replace(/<tr/g, '#<tr')
                .replace(/\n/g, '')
                .split('#')
                .filter(row => row.includes(subdomain));

            console.log(`Found ${rows.length} rows containing ${subdomain}`);

            if (rows.length === 0) {
                return {
                    success: true,
                    subdomain,
                    message: `A record not found in table: ${subdomain}`
                };
            }

            // Try to find record ID in any of the matching rows
            let recordId = null;
            for (const row of rows) {
                // Try multiple patterns to find record ID
                // Pattern 1: hosted_dns_recordid parameter (older format)
                let match = row.match(/hosted_dns_recordid=(\d+)/);
                if (match) {
                    recordId = match[1];
                    console.log(`Found record ID ${recordId} for ${subdomain} (via parameter)`);
                    break;
                }

                // Pattern 2: row id attribute (newer format)
                match = row.match(/id="(\d+)"/);
                if (match) {
                    recordId = match[1];
                    console.log(`Found record ID ${recordId} for ${subdomain} (via id attribute)`);
                    break;
                }

                // Pattern 3: hidden td with record ID
                match = row.match(/<td class="hidden">(\d+)<\/td>/);
                if (match) {
                    // Second hidden td usually contains the record ID
                    const hiddenIds = row.match(/<td class="hidden">(\d+)<\/td>/g);
                    if (hiddenIds && hiddenIds.length >= 2) {
                        recordId = hiddenIds[1].match(/(\d+)/)[1];
                        console.log(`Found record ID ${recordId} for ${subdomain} (via hidden td)`);
                        break;
                    }
                }
            }

            if (!recordId) {
                console.error(`Could not extract record ID from rows:`, rows[0].substring(0, 300));
                throw new Error(`Could not extract record ID for ${subdomain}`);
            }

            // Delete the record
            const deleteBody = `email=${usernameEncoded}&pass=${passwordEncoded}` +
                `&menu=edit_zone` +
                `&hosted_dns_zoneid=${zoneId}` +
                `&hosted_dns_recordid=${recordId}` +
                `&hosted_dns_editzone=1` +
                `&hosted_dns_delrecord=1` +
                `&hosted_dns_delconfirm=delete`;

            const deleteCmd = `curl -s 'https://dns.he.net/' \
        -b ${this.cookieFile} \
        --data '${deleteBody}'`;

            const { stdout: deleteResponse } = await execPromise(deleteCmd);

            // Check for success message
            if (deleteResponse.includes('Successfully removed record') ||
                deleteResponse.includes('dns_status')) {
                return {
                    success: true,
                    subdomain,
                    message: `A record deleted: ${subdomain}`
                };
            } else {
                throw new Error('Delete request sent but no success confirmation received');
            }
        } catch (error) {
            throw new Error(`Failed to delete A record: ${error.message}`);
        }
    }

    /**
     * Get base domain from full domain
     * e.g., 'api.trtek.net.tr' -> 'trtek.net.tr'
     */
    static getBaseDomain(fullDomain) {
        const parts = fullDomain.split('.');
        if (parts.length >= 3) {
            // Handle .com.tr, .net.tr, etc.
            if (parts[parts.length - 2] === 'com' || parts[parts.length - 2] === 'net' || parts[parts.length - 2] === 'org') {
                return parts.slice(-3).join('.');
            }
            return parts.slice(-2).join('.');
        }
        return fullDomain;
    }
}

module.exports = HEDNSManager;
