import React, { useEffect, useRef, useState } from "react";
import * as THREE from "three";
import { RoomEnvironment } from "three/examples/jsm/environments/RoomEnvironment.js";
import { Shield } from "lucide-react";

interface SecurityShield3DProps {
  /** Optional 0–100 security score that shifts core coloration (emerald -> amber -> crimson) */
  score?: number;
  /** Compact mode for dashboard / score cards; full mode for hero */
  variant?: "hero" | "compact";
  className?: string;
}

// Reusable math objects outside render loop (zero per-frame GC)
const _dummy = new THREE.Object3D();
const _color = new THREE.Color();

function createRadialShadowTexture(): THREE.CanvasTexture {
  const canvas = document.createElement("canvas");
  canvas.width = 256;
  canvas.height = 256;
  const ctx = canvas.getContext("2d");
  if (ctx) {
    const grad = ctx.createRadialGradient(128, 128, 12, 128, 128, 124);
    grad.addColorStop(0, "rgba(0, 0, 0, 0.65)");
    grad.addColorStop(0.55, "rgba(0, 0, 0, 0.22)");
    grad.addColorStop(1, "rgba(0, 0, 0, 0)");
    ctx.fillStyle = grad;
    ctx.fillRect(0, 0, 256, 256);
  }
  const tex = new THREE.CanvasTexture(canvas);
  tex.colorSpace = THREE.SRGBColorSpace;
  return tex;
}

function createHexFrameGeometry(outerR: number, innerR: number, depth: number): THREE.ExtrudeGeometry {
  const shape = new THREE.Shape();
  for (let i = 0; i < 6; i++) {
    const angle = (i / 6) * Math.PI * 2 + Math.PI / 6;
    const x = Math.cos(angle) * outerR;
    const y = Math.sin(angle) * outerR;
    if (i === 0) shape.moveTo(x, y);
    else shape.lineTo(x, y);
  }
  shape.closePath();

  const hole = new THREE.Path();
  for (let i = 0; i < 6; i++) {
    const angle = (i / 6) * Math.PI * 2 + Math.PI / 6;
    const x = Math.cos(angle) * innerR;
    const y = Math.sin(angle) * innerR;
    if (i === 0) hole.moveTo(x, y);
    else hole.lineTo(x, y);
  }
  hole.closePath();
  shape.holes.push(hole);

  const geo = new THREE.ExtrudeGeometry(shape, {
    depth,
    bevelEnabled: true,
    bevelThickness: 0.06,
    bevelSize: 0.05,
    bevelSegments: 3,
  });
  geo.center();
  return geo;
}

export function SecurityShield3D({
  score = 92,
  variant = "hero",
  className = "",
}: SecurityShield3DProps) {
  const mountRef = useRef<HTMLDivElement | null>(null);
  const scoreRef = useRef<number>(score);
  scoreRef.current = score;

  const [webglFailed, setWebglFailed] = useState(false);

  useEffect(() => {
    const container = mountRef.current;
    if (!container) return;

    const prefersReducedMotion =
      typeof window !== "undefined" &&
      window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;

    let isSoftwareGl = false;
    try {
      const probeCanvas = document.createElement("canvas");
      const gl = probeCanvas.getContext("webgl2") || probeCanvas.getContext("webgl");
      if (!gl) {
        setWebglFailed(true);
        return;
      }
      const ext = gl.getExtension("WEBGL_debug_renderer_info");
      const param = ext ? ext.UNMASKED_RENDERER_WEBGL : gl.RENDERER;
      const gpu = String(gl.getParameter(param) || "");
      gl.getExtension("WEBGL_lose_context")?.loseContext();
      isSoftwareGl = /SwiftShader|llvmpipe|softpipe|Software|Basic Render/i.test(gpu);
    } catch {
      setWebglFailed(true);
      return;
    }

    const width = container.clientWidth || (variant === "hero" ? 560 : 280);
    const height = container.clientHeight || (variant === "hero" ? 420 : 220);

    const scene = new THREE.Scene();
    scene.background = new THREE.Color(0xedf3e5);
    scene.fog = new THREE.FogExp2(0xedf3e5, variant === "hero" ? 0.042 : 0.056);

    const camera = new THREE.PerspectiveCamera(
      variant === "hero" ? 42 : 40,
      width / height,
      0.1,
      60
    );
    camera.position.set(0, variant === "hero" ? 0.85 : 0.65, variant === "hero" ? 6.2 : 5.6);
    camera.lookAt(0, 0, 0);

    let renderer: THREE.WebGLRenderer;
    try {
      renderer = new THREE.WebGLRenderer({
        antialias: !isSoftwareGl,
        powerPreference: "high-performance",
      });
    } catch {
      setWebglFailed(true);
      return;
    }

    renderer.outputColorSpace = THREE.SRGBColorSpace;
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.15;
    renderer.setPixelRatio(isSoftwareGl ? 1 : Math.min(window.devicePixelRatio || 1, 2));
    renderer.setSize(width, height);
    renderer.shadowMap.enabled = !isSoftwareGl;
    renderer.shadowMap.type = THREE.PCFSoftShadowMap;
    renderer.domElement.style.display = "block";
    renderer.domElement.style.width = "100%";
    renderer.domElement.style.height = "100%";
    renderer.domElement.style.touchAction = "pan-y";

    container.appendChild(renderer.domElement);

    const handleContextLost = (e: Event) => {
      e.preventDefault();
      setWebglFailed(true);
    };
    const handleContextRestored = () => {
      setWebglFailed(false);
    };
    renderer.domElement.addEventListener("webglcontextlost", handleContextLost);
    renderer.domElement.addEventListener("webglcontextrestored", handleContextRestored);

    // Studio environment map for realistic PBR reflections
    const pmremGenerator = new THREE.PMREMGenerator(renderer);
    const roomEnv = new RoomEnvironment();
    const envTarget = pmremGenerator.fromScene(roomEnv, 0.04);
    scene.environment = envTarget.texture;
    roomEnv.dispose();
    pmremGenerator.dispose();

    // 3-Point Studio Lighting Rig
    const hemiLight = new THREE.HemisphereLight(0xfffdf5, 0xc9dbba, 1.05);
    scene.add(hemiLight);

    const keyLight = new THREE.DirectionalLight(0xfffaf0, 2.0);
    keyLight.position.set(4.5, 6.0, 5.0);
    if (!isSoftwareGl) {
      keyLight.castShadow = true;
      keyLight.shadow.mapSize.set(1024, 1024);
      keyLight.shadow.camera.near = 1;
      keyLight.shadow.camera.far = 20;
      keyLight.shadow.camera.left = -4;
      keyLight.shadow.camera.right = 4;
      keyLight.shadow.camera.top = 4;
      keyLight.shadow.camera.bottom = -4;
      keyLight.shadow.bias = -0.0005;
      keyLight.shadow.normalBias = 0.02;
    }
    scene.add(keyLight);

    const rimLight = new THREE.DirectionalLight(0xa3cf8e, 1.6);
    rimLight.position.set(-4.5, 2.5, -4.0);
    scene.add(rimLight);

    // Composite 7-Part Procedural Security Assembly
    const assembly = new THREE.Group();
    assembly.position.y = 0.2;
    scene.add(assembly);

    const disposables: Array<{ dispose: () => void }> = [];

    // 1. Primary Armored Hexagonal Bevel Frame (Satin Sage-Titanium)
    const hexGeo = createHexFrameGeometry(1.72, 1.34, 0.24);
    const obsidianMat = new THREE.MeshPhysicalMaterial({
      color: 0x3e5642,
      metalness: 0.72,
      roughness: 0.28,
      clearcoat: 0.55,
      clearcoatRoughness: 0.2,
      anisotropy: 0.65,
    });
    const hexMesh = new THREE.Mesh(hexGeo, obsidianMat);
    hexMesh.castShadow = !isSoftwareGl;
    hexMesh.receiveShadow = !isSoftwareGl;
    assembly.add(hexMesh);
    disposables.push(hexGeo, obsidianMat);

    // 2. Secondary Warm Cream Gimbal Ring
    const gimbalGeo = new THREE.TorusGeometry(1.16, 0.045, 20, 84);
    const amberMetalMat = new THREE.MeshStandardMaterial({
      color: 0xf5ebd2,
      metalness: 0.45,
      roughness: 0.24,
      emissive: 0xd4c39b,
      emissiveIntensity: 0.28,
    });
    const gimbalMesh = new THREE.Mesh(gimbalGeo, amberMetalMat);
    gimbalMesh.rotation.x = Math.PI * 0.18;
    gimbalMesh.castShadow = !isSoftwareGl;
    assembly.add(gimbalMesh);
    disposables.push(gimbalGeo, amberMetalMat);

    // 3. Counter-Rotating Pastel Pista Telemetry Ring
    const telemetryGeo = new THREE.TorusGeometry(1.98, 0.026, 16, 96, Math.PI * 1.45);
    const emeraldRingMat = new THREE.MeshStandardMaterial({
      color: 0x82b96c,
      metalness: 0.45,
      roughness: 0.26,
      emissive: 0x5a9448,
      emissiveIntensity: 0.6,
    });
    const telemetryRing = new THREE.Mesh(telemetryGeo, emeraldRingMat);
    telemetryRing.rotation.set(-Math.PI * 0.32, Math.PI * 0.14, 0);
    assembly.add(telemetryRing);
    disposables.push(telemetryGeo, emeraldRingMat);

    // 4. Faceted Crystalline Pistachio Security Core
    const coreGeo = new THREE.IcosahedronGeometry(0.76, 1);
    const coreMat = new THREE.MeshPhysicalMaterial({
      color: 0x8ec477,
      metalness: 0.1,
      roughness: 0.14,
      transmission: isSoftwareGl ? 0 : 0.84,
      transparent: true,
      opacity: isSoftwareGl ? 0.65 : 1.0,
      ior: 1.65,
      thickness: 1.3,
      attenuationColor: new THREE.Color(0x5a9448),
      attenuationDistance: 1.8,
      clearcoat: 1.0,
      clearcoatRoughness: 0.08,
      emissive: 0x467638,
      emissiveIntensity: 0.32,
    });
    const coreMesh = new THREE.Mesh(coreGeo, coreMat);
    coreMesh.castShadow = !isSoftwareGl;
    assembly.add(coreMesh);
    disposables.push(coreGeo, coreMat);

    // 5. Inner Precision Cream Wireframe Lattice
    const latticeGeo = new THREE.EdgesGeometry(new THREE.IcosahedronGeometry(0.84, 0), 1);
    const latticeMat = new THREE.LineBasicMaterial({
      color: 0xfaf5e6,
      transparent: true,
      opacity: 0.82,
    });
    const latticeMesh = new THREE.LineSegments(latticeGeo, latticeMat);
    assembly.add(latticeMesh);
    disposables.push(latticeGeo, latticeMat);

    // 6. Grounded Travertine Cream Pedestal Plinth & Contact Shadow Plane
    const plinthGroup = new THREE.Group();
    plinthGroup.position.y = -2.05;
    scene.add(plinthGroup);

    const plinthGeo = new THREE.CylinderGeometry(1.45, 1.72, 0.16, 48);
    const plinthMat = new THREE.MeshStandardMaterial({
      color: 0xe6decb,
      metalness: 0.15,
      roughness: 0.65,
    });
    const plinthMesh = new THREE.Mesh(plinthGeo, plinthMat);
    plinthMesh.receiveShadow = !isSoftwareGl;
    plinthGroup.add(plinthMesh);

    const collarGeo = new THREE.TorusGeometry(1.46, 0.018, 12, 64);
    const collarMesh = new THREE.Mesh(collarGeo, emeraldRingMat);
    collarMesh.rotation.x = Math.PI / 2;
    collarMesh.position.y = 0.09;
    plinthGroup.add(collarMesh);

    const shadowTex = createRadialShadowTexture();
    const shadowPlaneGeo = new THREE.PlaneGeometry(4.4, 4.4);
    const shadowPlaneMat = new THREE.MeshBasicMaterial({
      map: shadowTex,
      transparent: true,
      depthWrite: false,
      opacity: 0.35,
    });
    const shadowPlane = new THREE.Mesh(shadowPlaneGeo, shadowPlaneMat);
    shadowPlane.rotation.x = -Math.PI / 2;
    shadowPlane.position.y = 0.09;
    plinthGroup.add(shadowPlane);
    disposables.push(plinthGeo, plinthMat, collarGeo, shadowTex, shadowPlaneGeo, shadowPlaneMat);

    // 7. Orbiting Verification Nodes (InstancedMesh)
    const nodeCount = 48;
    const nodeGeo = new THREE.OctahedronGeometry(0.042, 0);
    const nodeMat = new THREE.MeshStandardMaterial({
      color: 0xffffff,
      metalness: 0.35,
      roughness: 0.25,
      emissive: 0x6ca358,
      emissiveIntensity: 0.35,
    });
    const nodeInstances = new THREE.InstancedMesh(nodeGeo, nodeMat, nodeCount);
    nodeInstances.frustumCulled = false;

    const nodeMeta = Array.from({ length: nodeCount }, (_, idx) => {
      const orbitR = 2.05 + (idx % 5) * 0.22;
      const speed = (0.28 + (idx % 7) * 0.06) * (idx % 2 === 0 ? 1 : -1);
      const tilt = ((idx % 9) - 4) * 0.14;
      const phase = (idx / nodeCount) * Math.PI * 2;
      const scale = 0.75 + (idx % 4) * 0.18;
      _color.setHex(idx % 3 === 0 ? 0xf5ebd2 : 0x88c070);
      nodeInstances.setColorAt(idx, _color);
      return { orbitR, speed, tilt, phase, scale };
    });
    if (nodeInstances.instanceColor) {
      nodeInstances.instanceColor.needsUpdate = true;
    }
    nodeInstances.computeBoundingSphere();
    assembly.add(nodeInstances);
    disposables.push(nodeGeo, nodeMat);

    if (!isSoftwareGl) {
      renderer.compile(scene, camera);
    }

    // Interactive pointer parallax & drag rotation
    let pointerX = 0;
    let pointerY = 0;
    let dragging = false;
    let dragStartX = 0;
    let dragStartY = 0;
    let targetDragYaw = 0;
    let targetDragPitch = 0;
    let currentYaw = 0;
    let currentPitch = 0;

    const onPointerDown = (e: PointerEvent) => {
      dragging = true;
      dragStartX = e.clientX;
      dragStartY = e.clientY;
    };
    const onPointerMove = (e: PointerEvent) => {
      const rect = renderer.domElement.getBoundingClientRect();
      if (rect.width > 0 && rect.height > 0) {
        pointerX = ((e.clientX - rect.left) / rect.width) * 2 - 1;
        pointerY = ((e.clientY - rect.top) / rect.height) * 2 - 1;
      }
      if (dragging) {
        const dx = e.clientX - dragStartX;
        const dy = e.clientY - dragStartY;
        dragStartX = e.clientX;
        dragStartY = e.clientY;
        targetDragYaw += dx * 0.008;
        targetDragPitch = THREE.MathUtils.clamp(targetDragPitch + dy * 0.006, -0.55, 0.55);
      }
    };
    const onPointerUp = () => {
      dragging = false;
    };

    renderer.domElement.addEventListener("pointerdown", onPointerDown);
    window.addEventListener("pointermove", onPointerMove);
    window.addEventListener("pointerup", onPointerUp);

    let lastW = width;
    let lastH = height;
    let resizeRafId = 0;

    const applyResize = () => {
      resizeRafId = 0;
      if (disposed || !container) return;
      const nextW = container.clientWidth;
      const nextH = container.clientHeight;
      if (nextW <= 0 || nextH <= 0 || (nextW === lastW && nextH === lastH)) {
        return;
      }
      lastW = nextW;
      lastH = nextH;
      camera.aspect = nextW / nextH;
      camera.updateProjectionMatrix();
      renderer.setSize(nextW, nextH, false);
    };

    const handleResize = () => {
      if (resizeRafId) cancelAnimationFrame(resizeRafId);
      resizeRafId = requestAnimationFrame(applyResize);
    };
    const resizeObserver = new ResizeObserver(handleResize);
    resizeObserver.observe(container);

    const clock = new THREE.Clock();
    let frameId = 0;
    let disposed = false;

    function afterDraw(cb: () => void) {
      const gl = renderer.getContext() as WebGL2RenderingContext;
      if (!gl || typeof gl.fenceSync !== "function") {
        frameId = window.setTimeout(cb, 80);
        return;
      }
      const sync = gl.fenceSync(gl.SYNC_GPU_COMMANDS_COMPLETE, 0);
      gl.flush();
      const poll = () => {
        if (disposed) {
          if (sync) gl.deleteSync(sync);
          return;
        }
        const state = sync && gl.getSyncParameter(sync, gl.SYNC_STATUS);
        if (state === gl.UNSIGNALED) {
          frameId = window.setTimeout(poll, 5);
        } else {
          if (sync) gl.deleteSync(sync);
          frameId = window.setTimeout(cb, 80);
        }
      };
      frameId = window.setTimeout(poll, 5);
    }

    const updateCoreTint = () => {
      const s = scoreRef.current;
      if (s >= 75) {
        coreMat.color.setHex(0x8ec477);
        coreMat.emissive.setHex(0x467638);
        coreMat.attenuationColor.setHex(0x5a9448);
        emeraldRingMat.color.setHex(0x82b96c);
      } else if (s >= 45) {
        coreMat.color.setHex(0xf59e0b);
        coreMat.emissive.setHex(0x92400e);
        coreMat.attenuationColor.setHex(0xd97706);
        emeraldRingMat.color.setHex(0xf59e0b);
      } else {
        coreMat.color.setHex(0xef4444);
        coreMat.emissive.setHex(0x991b1b);
        coreMat.attenuationColor.setHex(0xdc2626);
        emeraldRingMat.color.setHex(0xef4444);
      }
    };

    const tick = () => {
      if (disposed) return;
      const delta = Math.min(clock.getDelta(), 0.1);
      const elapsed = clock.getElapsedTime();

      updateCoreTint();

      if (!prefersReducedMotion) {
        // Gentle idle float & multi-axis gyroscope kinematics
        assembly.position.y = 0.2 + Math.sin(elapsed * 1.15) * 0.06;
        hexMesh.rotation.y = Math.sin(elapsed * 0.35) * 0.18;
        gimbalMesh.rotation.y += delta * 0.48;
        gimbalMesh.rotation.z += delta * 0.22;
        telemetryRing.rotation.z -= delta * 0.55;
        coreMesh.rotation.y += delta * 0.38;
        coreMesh.rotation.x += delta * 0.2;
        latticeMesh.rotation.y -= delta * 0.28;
        latticeMesh.rotation.z += delta * 0.15;

        for (let i = 0; i < nodeCount; i++) {
          const m = nodeMeta[i];
          const a = m.phase + elapsed * m.speed;
          const x = Math.cos(a) * m.orbitR;
          const z = Math.sin(a) * m.orbitR;
          const y = Math.sin(a * 1.5 + m.phase) * m.tilt;
          _dummy.position.set(x, y, z);
          _dummy.rotation.set(elapsed + i, elapsed * 0.7, 0);
          _dummy.scale.setScalar(m.scale);
          _dummy.updateMatrix();
          nodeInstances.setMatrixAt(i, _dummy.matrix);
        }
        nodeInstances.instanceMatrix.needsUpdate = true;
      }

      // Smooth exponential damping for pointer parallax + drag
      const desiredYaw = targetDragYaw + pointerX * 0.24;
      const desiredPitch = targetDragPitch + pointerY * 0.14;
      currentYaw = THREE.MathUtils.damp(currentYaw, desiredYaw, 5.5, delta);
      currentPitch = THREE.MathUtils.damp(currentPitch, desiredPitch, 5.5, delta);
      assembly.rotation.y = currentYaw;
      assembly.rotation.x = currentPitch;

      renderer.render(scene, camera);

      if (prefersReducedMotion) {
        return;
      }
      if (isSoftwareGl) {
        afterDraw(tick);
      } else {
        frameId = requestAnimationFrame(tick);
      }
    };

    tick();

    return () => {
      disposed = true;
      cancelAnimationFrame(frameId);
      cancelAnimationFrame(resizeRafId);
      clearTimeout(frameId);
      resizeObserver.disconnect();
      renderer.domElement.removeEventListener("pointerdown", onPointerDown);
      window.removeEventListener("pointermove", onPointerMove);
      window.removeEventListener("pointerup", onPointerUp);
      renderer.domElement.removeEventListener("webglcontextlost", handleContextLost);
      renderer.domElement.removeEventListener("webglcontextrestored", handleContextRestored);

      for (const item of disposables) {
        item.dispose();
      }
      envTarget.dispose();
      renderer.dispose();
      if (renderer.domElement.parentElement === container) {
        container.removeChild(renderer.domElement);
      }
    };
  }, [variant]);

  if (webglFailed) {
    return (
      <div
        className={`w-full h-full min-h-[240px] flex flex-col items-center justify-center p-6 bg-gradient-to-br from-[#FAF6ED] via-[#EEF4E5] to-[#DFECD2] ${className}`}
      >
        <Shield className="w-12 h-12 text-[#3D6A39] mb-3" />
        <p className="text-xs font-medium text-[#1B2B20] text-center">
          SecureScan Sentinel Core · Static Analysis Active
        </p>
      </div>
    );
  }

  return (
    <div
      ref={mountRef}
      aria-label="Interactive 3D SecureScan security posture core. Drag to rotate."
      className={`w-full h-full cursor-grab active:cursor-grabbing ${className}`}
    />
  );
}
