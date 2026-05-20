const fs = require('fs').promises;
const path = require('path');
const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);

const CRS_PATH = '/app/config/owasp-crs';
const RULES_PATH = path.join(CRS_PATH, 'rules');

class CRSManager {
    async listRules() {
        try {
            const files = await fs.readdir(RULES_PATH);
            const rules = [];

            for (const file of files) {
                // Only process .conf and .conf.disabled files
                if (!file.endsWith('.conf') && !file.endsWith('.conf.disabled')) {
                    continue;
                }

                const stats = await fs.stat(path.join(RULES_PATH, file));
                rules.push({
                    filename: file,
                    name: file.replace('.conf', '').replace('.disabled', ''),
                    enabled: file.endsWith('.conf'),
                    size: stats.size,
                    updated_at: stats.mtime
                });
            }

            // Sort by filename
            return rules.sort((a, b) => a.filename.localeCompare(b.filename));
        } catch (error) {
            console.error('Error listing CRS rules:', error);
            throw error;
        }
    }

    async getRuleContent(filename) {
        try {
            // Security check: prevent directory traversal
            const safeFilename = path.basename(filename);
            const filePath = path.join(RULES_PATH, safeFilename);

            return await fs.readFile(filePath, 'utf8');
        } catch (error) {
            console.error(`Error reading rule ${filename}:`, error);
            throw error;
        }
    }

    async saveRuleContent(filename, content) {
        try {
            const safeFilename = path.basename(filename);
            const filePath = path.join(RULES_PATH, safeFilename);

            await fs.writeFile(filePath, content, 'utf8');
            return { success: true };
        } catch (error) {
            console.error(`Error saving rule ${filename}:`, error);
            throw error;
        }
    }

    async toggleRule(filename, enable) {
        try {
            const safeFilename = path.basename(filename);
            // Remove .disabled if present to get base name
            const baseName = safeFilename.replace('.disabled', '');

            const currentPath = path.join(RULES_PATH, safeFilename);
            const newName = enable ? baseName : `${baseName}.disabled`;
            const newPath = path.join(RULES_PATH, newName);

            if (currentPath !== newPath) {
                await fs.rename(currentPath, newPath);
            }

            return { success: true, new_filename: newName, enabled: enable };
        } catch (error) {
            console.error(`Error toggling rule ${filename}:`, error);
            throw error;
        }
    }

    async reloadSPOA() {
        try {
            console.log('Reloading SPOA service...');
            // We need to restart the spoa container to pick up changes
            // This uses the same Docker socket access as HAProxy restart
            await execPromise('curl -X POST --unix-socket /var/run/docker.sock http://localhost/containers/haproxy-spoa/restart?t=5');
            console.log('SPOA service restarted');
            return { success: true };
        } catch (error) {
            console.error('Error restarting SPOA:', error);
            // Fallback if curl is not available or fails
            try {
                // This might fail if docker CLI is not installed in API container, but worth a try
                await execPromise('docker restart haproxy-spoa');
                return { success: true };
            } catch (e) {
                throw new Error('Failed to restart SPOA service: ' + error.message);
            }
        }
    }
}

module.exports = CRSManager;
