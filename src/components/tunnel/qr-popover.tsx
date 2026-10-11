import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { QrCode } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";

interface QrPopoverProps {
  url: string | null;
  disabled?: boolean;
}

const QR_SIZE = 180;

/** Button that opens a popover rendering the public URL as a QR code. */
export function QrPopover({ url, disabled }: QrPopoverProps) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    if (!open || !url || !canvasRef.current) return;
    const canvas = canvasRef.current;
    // qrcode is loaded on demand: only needed when the popover actually renders.
    let cancelled = false;
    import("qrcode")
      .then((QRCode) => {
        if (cancelled) return;
        return QRCode.default.toCanvas(canvas, url, {
          width: QR_SIZE,
          margin: 2,
          color: { dark: "#18181bff", light: "#ffffffff" },
          errorCorrectionLevel: "M",
        });
      })
      .catch(() => {
        // Rendering failure leaves the canvas blank; URL is still shown below.
      });
    return () => {
      cancelled = true;
    };
  }, [open, url]);

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          variant="ghost"
          size="icon-xs"
          disabled={disabled}
          className="text-muted-foreground hover:text-foreground"
          aria-label={t("qr.title")}
        >
          <QrCode className="size-3.5" />
        </Button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-auto p-4">
        <div className="flex flex-col items-center gap-3">
          <div className="overflow-hidden rounded-lg border bg-white p-1.5">
            <canvas ref={canvasRef} width={QR_SIZE} height={QR_SIZE} />
          </div>
          <div className="max-w-[220px] text-center">
            <p className="text-sm font-medium">{t("qr.title")}</p>
            <p className="mt-0.5 text-xs text-muted-foreground">
              {t("qr.description")}
            </p>
            {url ? (
              <p className="mt-2 break-all font-mono text-[11px] text-muted-foreground">
                {url}
              </p>
            ) : null}
          </div>
        </div>
      </PopoverContent>
    </Popover>
  );
}
