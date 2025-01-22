import React, { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "./components/ui/card";
import { ArrowRight } from "lucide-react";

const INIT_MR = "0".repeat(96);

// Helper function to convert hex string to Uint8Array
const hexToUint8Array = (hex: string): Uint8Array => {
  const pairs = hex.match(/[\dA-F]{2}/gi) || [];
  return new Uint8Array(pairs.map((s: string) => parseInt(s, 16)));
};

// Helper function to convert Uint8Array to hex string
const uint8ArrayToHex = (uint8Array: Uint8Array): string => {
  return Array.from(uint8Array)
    .map((b: number) => b.toString(16).padStart(2, "0"))
    .join("");
};

const rtmrReplay = async (history: string[]): Promise<string> => {
  if (history.length === 0) return INIT_MR;

  let mr = hexToUint8Array(INIT_MR);
  for (const content of history) {
    try {
      let contentArray = hexToUint8Array(content);
      if (contentArray.length < 48) {
        const paddedArray = new Uint8Array(48);
        paddedArray.set(contentArray);
        contentArray = paddedArray;
      }

      const combined = new Uint8Array(mr.length + contentArray.length);
      combined.set(mr);
      combined.set(contentArray, mr.length);
      const hashBuffer = await crypto.subtle.digest("SHA-384", combined);
      mr = new Uint8Array(hashBuffer);
    } catch (error) {
      console.error("Error in rtmrReplay:", error);
      return "";
    }
  }
  return uint8ArrayToHex(mr);
};

const calcDigest = async (
  eventName: string,
  eventValue: string
): Promise<string> => {
  if (!eventValue) return "";
  try {
    const dstackEventTag = new Uint8Array(4);
    new DataView(dstackEventTag.buffer).setUint32(0, 0x08000001, true);

    const eventNameBytes = new TextEncoder().encode(eventName);
    const separator = new TextEncoder().encode(":");
    const valueBytes = hexToUint8Array(eventValue);

    const totalLength =
      dstackEventTag.length +
      separator.length * 2 +
      eventNameBytes.length +
      valueBytes.length;
    const combined = new Uint8Array(totalLength);
    let offset = 0;

    combined.set(dstackEventTag, offset);
    offset += dstackEventTag.length;
    combined.set(separator, offset);
    offset += separator.length;
    combined.set(eventNameBytes, offset);
    offset += eventNameBytes.length;
    combined.set(separator, offset);
    offset += separator.length;
    combined.set(valueBytes, offset);

    const hashBuffer = await crypto.subtle.digest("SHA-384", combined);
    return uint8ArrayToHex(new Uint8Array(hashBuffer));
  } catch (error) {
    console.error("Error in calcDigest:", error);
    return "";
  }
};

const getComposeHash = async (composeContent: string): Promise<string> => {
  if (!composeContent.trim()) return "";

  try {
    let manifestDict: Record<string, any>;
    try {
      manifestDict = JSON.parse(composeContent);
    } catch (e) {
      console.log("Invalid JSON, treating as yaml/raw content");
      manifestDict = { content: composeContent };
    }

    // Create adjusted manifest with empty docker_config
    const adjustedManifest = { ...manifestDict, docker_config: {} };

    // Ensure consistent serialization
    const manifestString = JSON.stringify(adjustedManifest, null, 0);
    console.log("Manifest string:", manifestString);

    const encoder = new TextEncoder();
    const data = encoder.encode(manifestString);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hash = uint8ArrayToHex(new Uint8Array(hashBuffer));
    console.log("Compose hash:", hash);
    return hash;
  } catch (error) {
    console.error("Error in getComposeHash:", error);
    return "";
  }
};

interface FlowBoxProps {
  title: string;
  value: string;
  className?: string;
}

const FlowBox: React.FC<FlowBoxProps> = ({ title, value, className = "" }) => (
  <Card className={`w-64 ${className}`}>
    <CardHeader className="p-4">
      <CardTitle className="text-sm font-medium">{title}</CardTitle>
    </CardHeader>
    <CardContent className="p-4 pt-0">
      <p className="text-xs break-all font-mono">{value || "..."}</p>
    </CardContent>
  </Card>
);

const Arrow = () => (
  <div className="flex items-center justify-center w-16">
    <ArrowRight className="text-gray-400" />
  </div>
);

interface Inputs {
  composeContent: string;
  rootFsHash: string;
  appId: string;
  caCertHash: string;
  instanceId: string;
}

interface Digests {
  rootFsHash: string;
  appId: string;
  composeHash: string;
  caCertHash: string;
  instanceId: string;
}

interface Calculated {
  composeHash: string;
  digests: Digests;
  rtmr3: string;
}

export default function RTMR3Calculator() {
  const [inputs, setInputs] = useState<Inputs>({
    composeContent: "",
    rootFsHash: "",
    appId: "",
    caCertHash: "",
    instanceId: "",
  });

  const [calculated, setCalculated] = useState<Calculated>({
    composeHash: "",
    digests: {
      rootFsHash: "",
      appId: "",
      composeHash: "",
      caCertHash: "",
      instanceId: "",
    },
    rtmr3: "",
  });

  useEffect(() => {
    let isMounted = true;

    const calculateValues = async () => {
      try {
        // Calculate compose hash
        const composeHash = await getComposeHash(inputs.composeContent);
        console.log("New compose hash:", composeHash);

        // Calculate all digests
        const digests = {
          rootFsHash: await calcDigest("rootfs-hash", inputs.rootFsHash),
          appId: await calcDigest("app-id", inputs.appId),
          composeHash: await calcDigest("compose-hash", composeHash),
          caCertHash: await calcDigest("ca-cert-hash", inputs.caCertHash),
          instanceId: await calcDigest("instance-id", inputs.instanceId),
        };

        // Calculate RTMR3 only if all digests are available
        const digestValues = Object.values(digests);
        const rtmr3 = digestValues.every((v) => v)
          ? await rtmrReplay(digestValues)
          : "";

        if (isMounted) {
          setCalculated({ composeHash, digests, rtmr3 });
        }
      } catch (error) {
        console.error("Calculation error:", error);
      }
    };

    calculateValues();
    return () => {
      isMounted = false;
    };
  }, [inputs]);

  return (
    <div className="p-6 max-w-7xl mx-auto">
      <Card className="mb-8">
        <CardHeader>
          <CardTitle>RTMR3 Calculator</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <textarea
              className="w-full h-32 p-2 border rounded font-mono text-sm"
              placeholder="Paste your docker-compose.yml content here..."
              value={inputs.composeContent}
              onChange={(e) =>
                setInputs((prev) => ({
                  ...prev,
                  composeContent: e.target.value,
                }))
              }
            />
            {["rootFsHash", "appId", "caCertHash", "instanceId"].map(
              (field) => (
                <input
                  key={field}
                  className="w-full p-2 border rounded font-mono text-sm"
                  placeholder={field}
                  value={inputs[field as keyof Inputs]}
                  onChange={(e) =>
                    setInputs((prev) => ({ ...prev, [field]: e.target.value }))
                  }
                />
              )
            )}
          </div>
        </CardContent>
      </Card>

      <div className="space-y-8">
        <div className="flex flex-wrap gap-4 items-center justify-center">
          <FlowBox title="Compose Hash" value={calculated.composeHash} />
          <Arrow />
          <FlowBox
            title="Compose Hash Digest"
            value={calculated.digests.composeHash}
          />
        </div>

        <div className="flex flex-wrap gap-4 items-center justify-center">
          {[
            { title: "Root FS Hash", key: "rootFsHash" },
            { title: "App ID", key: "appId" },
            { title: "CA Cert Hash", key: "caCertHash" },
            { title: "Instance ID", key: "instanceId" },
          ].map(({ title, key }) => (
            <div key={key} className="flex items-center">
              <FlowBox title={title} value={inputs[key as keyof Inputs]} />
              <Arrow />
              <FlowBox
                title={`${title} Digest`}
                value={calculated.digests[key as keyof Digests]}
              />
            </div>
          ))}
        </div>

        <div className="flex flex-wrap gap-4 items-center justify-center">
          <FlowBox
            title="Final RTMR3"
            value={calculated.rtmr3}
            className="w-full max-w-2xl"
          />
        </div>
      </div>
    </div>
  );
}
