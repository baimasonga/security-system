-- Fixed Rokela Android anonymous analytics; never authority or customer document data.
CREATE TABLE mobile_analytics_events (
  id uuid PRIMARY KEY,
  installation text NOT NULL CHECK (installation ~ '^[a-f0-9]{64}$'),
  digest text NOT NULL CHECK (digest ~ '^[a-f0-9]{64}$'),
  occurred_at timestamptz NOT NULL,
  received_at timestamptz NOT NULL,
  feature text NOT NULL CHECK (feature IN ('app_open','open','scan','sign','edit','pages','merge','photos','compress','protect','unlock','ocr','fill','convert')),
  app_version text NOT NULL CHECK (app_version ~ '^[0-9]{1,4}(\.[0-9]{1,4}){0,3}$'),
  os_major integer CHECK (os_major BETWEEN 1 AND 99),
  device_class text NOT NULL CHECK (device_class IN ('phone','tablet','unknown')),
  country text CHECK (country ~ '^[A-Z]{2}$')
);
CREATE INDEX mobile_analytics_received ON mobile_analytics_events(received_at);
