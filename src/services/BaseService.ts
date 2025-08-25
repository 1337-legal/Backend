class BaseService {
    public checkEnvironment(name: string[]): { [key: string]: string } {
        const values: { [key: string]: string } = {}

        for (const envName of name) {
            const value = Bun.env[envName];
            if (value) {
                values[envName] = value;
            } else {
                console.error(`Environment variable ${envName} is not set.`);
                process.exit(1);
            }
        }

        return values;
    }
}

export default BaseService;