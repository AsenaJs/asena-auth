import { createTestApp } from '@asenajs/asena/test';
import { AsenaAuthService, Auth } from '../../index';
import { FakeAdapter } from '../support/fakeAdapter';

@Auth({ sessionTtl: 3600, absoluteTtl: 60 })
class Inverted extends AsenaAuthService {}

await createTestApp({ adapter: new FakeAdapter(), components: [Inverted] });
