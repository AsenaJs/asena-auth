import { createTestApp } from '@asenajs/asena/test';
import { createErgenecoreAdapter } from '@asenajs/ergenecore';
import { AsenaAuthService, Auth } from '../../index';

@Auth({ sessionTtl: 3600, absoluteTtl: 60 })
class Inverted extends AsenaAuthService {}

await createTestApp({ adapter: createErgenecoreAdapter(), components: [Inverted] });
