import { ScanEngineList } from '../../core/models/api.models';

/**
 * The scan engines are on (SECREVIEW_SCAN_ENGINE_TOKEN set) but none is active: the code scans
 * are refused (fallback ``refuse``, 503) or run by the Controller server itself (``local``).
 * Null while an engine is active or when the engines are off.
 */
export function scanEngineOutage(data: ScanEngineList): ScanEngineList['fallback'] | null {
  if (!data.enabled || data.engines.some((engine) => engine.active)) {
    return null;
  }
  return data.fallback;
}
