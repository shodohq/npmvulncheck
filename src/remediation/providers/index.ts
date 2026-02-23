import { DependencyManager } from "../../core/types";
import { ManifestOverrideProvider } from "./provider";
import { NpmOverridesProvider } from "./npmOverridesProvider";
import { PnpmOverridesProvider } from "./pnpmOverridesProvider";
import { YarnResolutionsProvider } from "./yarnResolutionsProvider";

const PROVIDERS: Record<DependencyManager, ManifestOverrideProvider> = {
  npm: new NpmOverridesProvider(),
  pnpm: new PnpmOverridesProvider(),
  yarn: new YarnResolutionsProvider()
};

export function getManifestOverrideProvider(manager: DependencyManager): ManifestOverrideProvider {
  return PROVIDERS[manager];
}
