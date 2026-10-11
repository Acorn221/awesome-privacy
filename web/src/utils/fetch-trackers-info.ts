import { fetchEnrich } from './fetch-enrich';

export const fetchTrackersInfo = (url: string): Promise<TrackersInfo | null> =>
  fetchEnrich<TrackersInfo>(
    'Trackers',
    `/v1/enrich/trackers?url=${encodeURIComponent(url)}`,
    url,
  );

export interface WebsiteTracker {
  domain: string;
  owner: string;
  categories: string[];
}

export interface TrackersInfo {
  finalUrl: string;
  trackers: WebsiteTracker[];
}
