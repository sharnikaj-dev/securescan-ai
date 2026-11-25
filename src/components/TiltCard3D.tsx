import React, { useRef, useState } from "react";

interface TiltCard3DProps {
  children: React.ReactNode;
  className?: string;
  maxTilt?: number;
  onClick?: () => void;
}

/**
 * Pointer-tracked 3D perspective card with subtle dynamic specular sheen.
 * Automatically disables tilt transform when prefers-reduced-motion is active.
 */
export function TiltCard3D({
  children,
  className = "",
  maxTilt = 6,
  onClick,
}: TiltCard3DProps) {
  const cardRef = useRef<HTMLDivElement | null>(null);
  const [transform, setTransform] = useState("perspective(1000px) rotateX(0deg) rotateY(0deg) translateZ(0px)");
  const [sheen, setSheen] = useState<{ x: number; y: number; active: boolean }>({
    x: 50,
    y: 50,
    active: false,
  });

  const handlePointerMove = (e: React.PointerEvent<HTMLDivElement>) => {
    if (
      typeof window !== "undefined" &&
      window.matchMedia?.("(prefers-reduced-motion: reduce)").matches
    ) {
      return;
    }
    const el = cardRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    if (rect.width <= 0 || rect.height <= 0) return;

    const relX = (e.clientX - rect.left) / rect.width;
    const relY = (e.clientY - rect.top) / rect.height;
    const rotY = (relX - 0.5) * 2 * maxTilt;
    const rotX = -(relY - 0.5) * 2 * maxTilt;

    setTransform(
      `perspective(1000px) rotateX(${rotX.toFixed(2)}deg) rotateY(${rotY.toFixed(2)}deg) translateZ(6px)`
    );
    setSheen({
      x: Math.round(relX * 100),
      y: Math.round(relY * 100),
      active: true,
    });
  };

  const handlePointerLeave = () => {
    setTransform("perspective(1000px) rotateX(0deg) rotateY(0deg) translateZ(0px)");
    setSheen((prev) => ({ ...prev, active: false }));
  };

  return (
    <div
      ref={cardRef}
      onPointerMove={handlePointerMove}
      onPointerLeave={handlePointerLeave}
      onClick={onClick}
      style={{
        transform,
        transformStyle: "preserve-3d",
        transition: sheen.active
          ? "transform 90ms ease-out, border-color 200ms ease, box-shadow 200ms ease"
          : "transform 360ms cubic-bezier(0.16, 1, 0.3, 1), border-color 200ms ease, box-shadow 360ms cubic-bezier(0.16, 1, 0.3, 1)",
      }}
      className={`relative overflow-hidden ${className}`}
    >
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 transition-opacity duration-300"
        style={{
          opacity: sheen.active ? 1 : 0,
          background: `radial-gradient(420px circle at ${sheen.x}% ${sheen.y}%, rgba(155, 197, 133, 0.24), rgba(250, 246, 237, 0.14) 38%, transparent 70%)`,
        }}
      />
      <div className="relative z-10 h-full">{children}</div>
    </div>
  );
}
