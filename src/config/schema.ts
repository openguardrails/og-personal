import { z } from "zod";

/**
 * OG Personal configuration schema
 */
export const OGConfigSchema = z.object({
  /** API key for XiangxinAI cloud service */
  apiKey: z.string().optional(),

  /** XiangxinAI API base URL */
  apiBaseUrl: z.string().default("https://api.xiangxinai.cn/v1"),

  /** Model to use for detection */
  model: z.string().default("Xiangxin-2XL-Chat"),

  /** Gateway server port */
  gatewayPort: z.number().int().min(1024).max(65535).default(18790),

  /** Enable desktop notifications */
  notifications: z
    .object({
      desktop: z.boolean().default(true),
      email: z
        .object({
          enabled: z.boolean().default(false),
          address: z.string().email().optional(),
        })
        .default({}),
    })
    .default({}),

  /** Detector settings */
  detectors: z
    .object({
      /** Protection detectors (attacks against agent) */
      protection: z
        .object({
          promptInjection: z.boolean().default(true),
          systemOverride: z.boolean().default(true),
          webAttacks: z.boolean().default(true),
          mcpPoisoning: z.boolean().default(true),
          maliciousCode: z.boolean().default(true),
        })
        .default({}),

      /** Supervision detectors (agent mistakes) */
      supervision: z
        .object({
          nsfw: z.boolean().default(true),
          pii: z.boolean().default(true),
          credentials: z.boolean().default(true),
          confidential: z.boolean().default(true),
          offTopic: z.boolean().default(false),
        })
        .default({}),
    })
    .default({}),

  /** Sensitivity levels (0-100, higher = more sensitive) */
  sensitivity: z
    .object({
      promptInjection: z.number().min(0).max(100).default(70),
      pii: z.number().min(0).max(100).default(80),
      credentials: z.number().min(0).max(100).default(90),
    })
    .default({}),

  /** Auto-remediation settings */
  autoRemediation: z
    .object({
      enabled: z.boolean().default(false),
      blockHighRisk: z.boolean().default(true),
      notifyOnBlock: z.boolean().default(true),
    })
    .default({}),

  /** Scan settings */
  scan: z
    .object({
      /** Interval between continuous scans (ms) */
      intervalMs: z.number().int().min(1000).default(30000),
      /** Watch for file changes */
      watchFiles: z.boolean().default(true),
    })
    .default({}),

  /** Transparent proxy settings */
  proxy: z
    .object({
      /** Enable transparent proxy mode */
      enabled: z.boolean().default(false),
      /** Port OG Personal listens on (takes over OpenClaw's original port) */
      listenPort: z.number().int().min(1024).max(65535).default(18789),
      /** Port OpenClaw is moved to (internal) */
      openclawInternalPort: z.number().int().min(1024).max(65535).default(18780),
      /** OpenClaw gateway auth token */
      openclawAuthToken: z.string().optional(),
    })
    .default({}),

  /** Last scan timestamp */
  lastScanAt: z.string().datetime().optional(),

  /** Onboarding completed */
  onboardingComplete: z.boolean().default(false),
});

export type OGConfig = z.infer<typeof OGConfigSchema>;

/** Default configuration */
export const DEFAULT_CONFIG: OGConfig = OGConfigSchema.parse({});
