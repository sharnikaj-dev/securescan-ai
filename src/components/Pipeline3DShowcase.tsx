import React, { useEffect, useRef, useState } from "react";
import * as THREE from "three";
import { RoomEnvironment } from "three/examples/jsm/environments/RoomEnvironment.js";
import { ChevronDown, ChevronUp, Cpu, RotateCcw } from "lucide-react";

export type PipelineStageId = "overview" | "isolate" | "ast" | "score" | "gemini";

export interface PipelineStageMeta {
  id: Exclude<PipelineStageId, "overview">;
  index: number;
  label: string;
  shortTitle: string;
  summary: string;
  techSpec: string;
  cameraPos: [number, number, number];
  lookAt: [number, number, number];
  nodePos: [number, number, number];
  accentHex: number;
}

export const PIPELINE_STAGES: PipelineStageMeta[] = [
  {
    id: "isolate",
    index: 0,
    label: "01. Archive Gate",
    shortTitle: "Untrusted File & ZIP Isolation",
    summary:
      "Every uploaded file or ZIP archive is quarantined, extension-filtered, checked for symlink escapes, and extracted under canonical path confinement without execution.",
    techSpec: "Max 25 MB archive · Path-traversal guard · Read-only UTF-8 parse",
    cameraPos: [-5.6, 2.35, 5.2],
    lookAt: [-4.5, 0.25, 0],
    nodePos: [-4.5, 0.25, 0],
    accentHex: 0x78b064,
  },
  {
    id: "ast",
    index: 1,
    label: "02. AST & Semgrep",
    shortTitle: "Python AST & Multi-Language SAST Lattice",
    summary:
      "Deterministic static inspection traverses Python syntax trees and Semgrep-compatible YAML patterns across Python, JS/TS, Java, PHP, C, and C++.",
    techSpec: "12 OWASP/CWE categories · Line-exact snippet extraction",
    cameraPos: [-1.5, 2.5, 5.1],
    lookAt: [-1.5, 0.3, 0],
    nodePos: [-1.5, 0.3, 0],
    accentHex: 0x95c97f,
  },
  {
    id: "score",
    index: 2,
    label: "03. Risk Scoring",
    shortTitle: "Weighted Security Scoring Core",
    summary:
      "Verified static findings are weighted by severity and vulnerability class to produce an application-defined 0–100 security posture score and trend telemetry.",
    techSpec: "Crit / High / Med / Low weighting · SQLite + PostgreSQL schema",
    cameraPos: [1.5, 2.5, 5.1],
    lookAt: [1.5, 0.3, 0],
    nodePos: [1.5, 0.3, 0],
    accentHex: 0xd9a04e,
  },
  {
    id: "gemini",
    index: 3,
    label: "04. Gemini Fix",
    shortTitle: "Gemini Remediation Synthesizer & PDF Export",
    summary:
      "Google Gemini analyzes concrete SAST findings on demand to generate plain-language risk explanations, exploit impact, corrected code, and executive PDF audit reports.",
    techSpec: "Grounded strictly on verified findings · Exportable PDF reports",
    cameraPos: [5.4, 2.35, 5.2],
    lookAt: [4.5, 0.25, 0],
    nodePos: [4.5, 0.25, 0],
    accentHex: 0x5d9452,
  },
];

const OVERVIEW_CAM: { pos: [number, number, number]; target: [number, number, number] } = {
  pos: [0, 3.3, 9.6],
  target: [0, 0.15, 0],
};

interface Pipeline3DShowcaseProps {
  selectedStage?: PipelineStageId;
  onSelectStage?: (stage: PipelineStageId) => void;
  className?: string;
}

const _dummy = new THREE.Object3D();
const _pt = new THREE.Vector3();

function createFloorGridTexture(): THREE.CanvasTexture {
  const canvas = document.createElement("canvas");
  canvas.width = 512;
  canvas.height = 512;
  const ctx = canvas.getContext("2d");
  if (ctx) {
    ctx.fillStyle = "#f4f1e6";
    ctx.fillRect(0, 0, 512, 512);
    ctx.strokeStyle = "rgba(104, 148, 86, 0.22)";
    ctx.lineWidth = 1;
    for (let i = 0; i <= 512; i += 32) {
      ctx.beginPath();
      ctx.moveTo(i, 0);
      ctx.lineTo(i, 512);
      ctx.stroke();
      ctx.beginPath();
      ctx.moveTo(0, i);
      ctx.lineTo(512, i);
      ctx.stroke();
    }
  }
  const tex = new THREE.CanvasTexture(canvas);
  tex.wrapS = THREE.RepeatWrapping;
  tex.wrapT = THREE.RepeatWrapping;
  tex.repeat.set(6, 4);
  tex.colorSpace = THREE.SRGBColorSpace;
  return tex;
}

export function Pipeline3DShowcase({
  selectedStage: controlledStage,
  onSelectStage,
  className = "",
}: Pipeline3DShowcaseProps) {
  const mountRef = useRef<HTMLDivElement | null>(null);
  const [internalStage, setInternalStage] = useState<PipelineStageId>("overview");
  const activeStage = controlledStage ?? internalStage;
  const activeStageRef = useRef<PipelineStageId>(activeStage);
  activeStageRef.current = activeStage;

  const [dockCollapsed, setDockCollapsed] = useState(false);
  const [webglFailed, setWebglFailed] = useState(false);

  const selectStage = (stage: PipelineStageId) => {
    setInternalStage(stage);
    onSelectStage?.(stage);
  };

  useEffect(() => {
    const container = mountRef.current;
    if (!container) return;

    const prefersReducedMotion =
      typeof window !== "undefined" &&
      window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;

    let isSoftwareGl = false;
    try {
      const probe = document.createElement("canvas");
      const gl = probe.getContext("webgl2") || probe.getContext("webgl");
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

    const width = container.clientWidth || 900;
    const height = container.clientHeight || 480;

    const scene = new THREE.Scene();
    scene.background = new THREE.Color(0xedf3e5);
    scene.fog = new THREE.FogExp2(0xedf3e5, 0.032);

    const camera = new THREE.PerspectiveCamera(42, width / height, 0.1, 80);
    camera.position.set(...OVERVIEW_CAM.pos);
    camera.lookAt(...OVERVIEW_CAM.target);

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
    renderer.toneMappingExposure = 1.1;
    renderer.setPixelRatio(isSoftwareGl ? 1 : Math.min(window.devicePixelRatio || 1, 2));
    renderer.setSize(width, height, false);
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

    const pmrem = new THREE.PMREMGenerator(renderer);
    const roomEnv = new RoomEnvironment();
    const envTarget = pmrem.fromScene(roomEnv, 0.04);
    scene.environment = envTarget.texture;
    roomEnv.dispose();
    pmrem.dispose();

    const hemi = new THREE.HemisphereLight(0xfffdf5, 0xc9dbba, 1.0);
    scene.add(hemi);

    const keyLight = new THREE.DirectionalLight(0xfffaf0, 1.9);
    keyLight.position.set(5, 8, 6);
    if (!isSoftwareGl) {
      keyLight.castShadow = true;
      keyLight.shadow.mapSize.set(1024, 1024);
      keyLight.shadow.camera.left = -8;
      keyLight.shadow.camera.right = 8;
      keyLight.shadow.camera.top = 5;
      keyLight.shadow.camera.bottom = -5;
      keyLight.shadow.bias = -0.0005;
    }
    scene.add(keyLight);

    const rimLight = new THREE.DirectionalLight(0x94c87c, 1.4);
    rimLight.position.set(-6, 3, -5);
    scene.add(rimLight);

    const disposables: Array<{ dispose: () => void }> = [];

    // Ground plane with subtle pistachio-cream architectural grid
    const gridTex = createFloorGridTexture();
    const floorGeo = new THREE.PlaneGeometry(24, 14);
    const floorMat = new THREE.MeshStandardMaterial({
      map: gridTex,
      roughness: 0.85,
      metalness: 0.1,
    });
    const floorMesh = new THREE.Mesh(floorGeo, floorMat);
    floorMesh.rotation.x = -Math.PI / 2;
    floorMesh.position.y = -1.35;
    floorMesh.receiveShadow = !isSoftwareGl;
    scene.add(floorMesh);
    disposables.push(gridTex, floorGeo, floorMat);

    // 4 Composite Stage Assemblies + Hitboxes for Raycasting
    const stageGroups: THREE.Group[] = [];
    const hitTargets: THREE.Mesh[] = [];
    const rotors: THREE.Object3D[] = [];
    const coreMaterials: THREE.MeshStandardMaterial[] = [];

    const baseGeo = new THREE.CylinderGeometry(0.95, 1.12, 0.22, 6);
    const collarGeo = new THREE.TorusGeometry(0.98, 0.025, 12, 48);
    const frameGeo = new THREE.OctahedronGeometry(0.72, 0);
    const coreGeo = new THREE.IcosahedronGeometry(0.42, 1);
    const ringGeo = new THREE.TorusGeometry(0.86, 0.024, 14, 64);
    const hitGeo = new THREE.CylinderGeometry(1.15, 1.15, 2.2, 12);
    const hitMat = new THREE.MeshBasicMaterial({ visible: false });
    disposables.push(baseGeo, collarGeo, frameGeo, coreGeo, ringGeo, hitGeo, hitMat);

    const baseMat = new THREE.MeshPhysicalMaterial({
      color: 0x3e5642,
      metalness: 0.58,
      roughness: 0.34,
      clearcoat: 0.45,
    });
    const wireMat = new THREE.MeshStandardMaterial({
      color: 0x6f9468,
      metalness: 0.4,
      roughness: 0.35,
      wireframe: true,
    });
    disposables.push(baseMat, wireMat);

    PIPELINE_STAGES.forEach((stage, idx) => {
      const group = new THREE.Group();
      group.position.set(stage.nodePos[0], 0, stage.nodePos[2]);
      scene.add(group);
      stageGroups.push(group);

      const accentMat = new THREE.MeshStandardMaterial({
        color: stage.accentHex,
        metalness: 0.55,
        roughness: 0.22,
        emissive: stage.accentHex,
        emissiveIntensity: 0.55,
      });
      coreMaterials.push(accentMat);
      disposables.push(accentMat);

      const base = new THREE.Mesh(baseGeo, baseMat);
      base.position.y = -1.24;
      base.castShadow = !isSoftwareGl;
      base.receiveShadow = !isSoftwareGl;
      group.add(base);

      const collar = new THREE.Mesh(collarGeo, accentMat);
      collar.rotation.x = Math.PI / 2;
      collar.position.y = -1.12;
      group.add(collar);

      const rotor = new THREE.Group();
      rotor.position.y = 0.25;
      group.add(rotor);
      rotors.push(rotor);

      const core = new THREE.Mesh(coreGeo, accentMat);
      core.castShadow = !isSoftwareGl;
      rotor.add(core);

      const cage = new THREE.Mesh(frameGeo, wireMat);
      rotor.add(cage);

      const ring = new THREE.Mesh(ringGeo, accentMat);
      ring.rotation.set(Math.PI * 0.28 * (idx % 2 === 0 ? 1 : -1), Math.PI * 0.2, 0);
      rotor.add(ring);

      const hitbox = new THREE.Mesh(hitGeo, hitMat);
      hitbox.position.y = -0.1;
      hitbox.userData = { stageId: stage.id };
      group.add(hitbox);
      hitTargets.push(hitbox);
    });

    // Connecting Curved Data Conduit & Flowing Packets (InstancedMesh)
    const conduitCurve = new THREE.CatmullRomCurve3([
      new THREE.Vector3(-4.5, 0.25, 0),
      new THREE.Vector3(-3.0, 0.52, -0.35),
      new THREE.Vector3(-1.5, 0.3, 0),
      new THREE.Vector3(0.0, 0.55, 0.35),
      new THREE.Vector3(1.5, 0.3, 0),
      new THREE.Vector3(3.0, 0.52, -0.35),
      new THREE.Vector3(4.5, 0.25, 0),
    ]);
    const tubeGeo = new THREE.TubeGeometry(conduitCurve, 96, 0.035, 10, false);
    const tubeMat = new THREE.MeshStandardMaterial({
      color: 0x5d8259,
      metalness: 0.45,
      roughness: 0.35,
      emissive: 0x3b5938,
      emissiveIntensity: 0.35,
    });
    const tubeMesh = new THREE.Mesh(tubeGeo, tubeMat);
    scene.add(tubeMesh);
    disposables.push(tubeGeo, tubeMat);

    const packetCount = 24;
    const packetGeo = new THREE.SphereGeometry(0.068, 12, 12);
    const packetMat = new THREE.MeshStandardMaterial({
      color: 0xfaf4e2,
      emissive: 0x86be70,
      emissiveIntensity: 0.9,
      roughness: 0.2,
    });
    const packets = new THREE.InstancedMesh(packetGeo, packetMat, packetCount);
    packets.frustumCulled = false;
    scene.add(packets);
    disposables.push(packetGeo, packetMat);

    if (!isSoftwareGl) {
      renderer.compile(scene, camera);
    }

    // Raycast click + hover parallax
    const raycaster = new THREE.Raycaster();
    const pointerNdc = new THREE.Vector2();
    let hoverX = 0;
    let hoverY = 0;

    const onPointerMove = (e: PointerEvent) => {
      const rect = renderer.domElement.getBoundingClientRect();
      if (rect.width <= 0 || rect.height <= 0) return;
      hoverX = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      hoverY = ((e.clientY - rect.top) / rect.height) * 2 - 1;
    };

    const onPointerClick = (e: MouseEvent) => {
      const rect = renderer.domElement.getBoundingClientRect();
      if (rect.width <= 0 || rect.height <= 0) return;
      pointerNdc.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      pointerNdc.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;
      raycaster.setFromCamera(pointerNdc, camera);
      const hits = raycaster.intersectObjects(hitTargets, false);
      if (hits.length > 0) {
        const hitId = hits[0].object.userData?.stageId as PipelineStageId | undefined;
        if (hitId) {
          selectStage(hitId);
        }
      }
    };

    renderer.domElement.addEventListener("pointermove", onPointerMove);
    renderer.domElement.addEventListener("click", onPointerClick);

    let lastW = width;
    let lastH = height;
    let resizeRafId = 0;
    let disposed = false;

    const applyResize = () => {
      resizeRafId = 0;
      if (disposed || !container) return;
      const nextW = container.clientWidth;
      const nextH = container.clientHeight;
      if (nextW <= 0 || nextH <= 0 || (nextW === lastW && nextH === lastH)) return;
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

    const camLook = new THREE.Vector3(...OVERVIEW_CAM.target);
    const clock = new THREE.Clock();
    let frameId = 0;

    function afterDraw(cb: () => void) {
      const gl = renderer.getContext() as WebGL2RenderingContext;
      if (!gl || typeof gl.fenceSync !== "function") {
        frameId = window.setTimeout(cb, 85);
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
          frameId = window.setTimeout(cb, 85);
        }
      };
      frameId = window.setTimeout(poll, 5);
    }

    const tick = () => {
      if (disposed) return;
      const delta = Math.min(clock.getDelta(), 0.1);
      const elapsed = clock.getElapsedTime();
      const current = activeStageRef.current;

      const stageObj = PIPELINE_STAGES.find((s) => s.id === current);
      const desiredPos = stageObj ? stageObj.cameraPos : OVERVIEW_CAM.pos;
      const desiredLook = stageObj ? stageObj.lookAt : OVERVIEW_CAM.target;

      camera.position.x = THREE.MathUtils.damp(
        camera.position.x,
        desiredPos[0] + hoverX * 0.32,
        4.5,
        delta
      );
      camera.position.y = THREE.MathUtils.damp(
        camera.position.y,
        desiredPos[1] - hoverY * 0.18,
        4.5,
        delta
      );
      camera.position.z = THREE.MathUtils.damp(camera.position.z, desiredPos[2], 4.5, delta);

      camLook.x = THREE.MathUtils.damp(camLook.x, desiredLook[0], 5.0, delta);
      camLook.y = THREE.MathUtils.damp(camLook.y, desiredLook[1], 5.0, delta);
      camLook.z = THREE.MathUtils.damp(camLook.z, desiredLook[2], 5.0, delta);
      camera.lookAt(camLook);

      if (!prefersReducedMotion) {
        rotors.forEach((rotor, idx) => {
          const isFocused = stageObj ? stageObj.index === idx : false;
          const speedBoost = isFocused ? 1.8 : 1.0;
          rotor.rotation.y += delta * 0.55 * speedBoost;
          rotor.rotation.x = Math.sin(elapsed * 1.1 + idx) * 0.18;
          rotor.position.y = 0.25 + Math.sin(elapsed * 1.4 + idx * 0.9) * 0.08;
          coreMaterials[idx].emissiveIntensity = isFocused ? 1.15 : 0.48;
        });

        for (let i = 0; i < packetCount; i++) {
          const t = ((i / packetCount) + elapsed * 0.14) % 1;
          conduitCurve.getPointAt(t, _pt);
          _dummy.position.copy(_pt);
          const pulse = 0.8 + Math.sin(elapsed * 4 + i) * 0.22;
          _dummy.scale.setScalar(pulse);
          _dummy.updateMatrix();
          packets.setMatrixAt(i, _dummy.matrix);
        }
        packets.instanceMatrix.needsUpdate = true;
      }

      renderer.render(scene, camera);

      if (prefersReducedMotion) return;
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
      renderer.domElement.removeEventListener("pointermove", onPointerMove);
      renderer.domElement.removeEventListener("click", onPointerClick);
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
  }, []);

  const currentStageMeta = PIPELINE_STAGES.find((s) => s.id === activeStage);

  return (
    <div className={`relative rounded-xl overflow-hidden border border-[#CBE0B9] dark:border-[#2A3D30] bg-[#EDF3E5] ${className}`}>
      <div className="h-[420px] sm:h-[490px] w-full relative">
        {webglFailed ? (
          <div className="w-full h-full flex flex-col items-center justify-center p-8 text-center">
            <Cpu className="w-12 h-12 text-[#3D6A39] mb-3" />
            <p className="text-sm font-medium text-[#1B2B20]">
              SecureScan 4-Stage SAST &amp; Gemini Pipeline
            </p>
            <p className="text-xs text-[#4C6150] mt-1 max-w-md">
              Select a stage below to inspect archive isolation, AST scanning, scoring, and Gemini synthesis.
            </p>
          </div>
        ) : (
          <div
            ref={mountRef}
            aria-label="Interactive 3D SAST Pipeline Visualization. Click any stage node to focus camera."
            className="w-full h-full cursor-pointer"
          />
        )}

        {/* Top-left lightweight instruction pill (opaque background, no backdrop-blur) */}
        <div className="pointer-events-none absolute top-3.5 left-4 px-3 py-1.5 rounded-lg bg-[#FFFDF7]/95 border border-[#CBE0B9] text-[11px] font-mono text-[#2F4534]">
          {currentStageMeta
            ? `${currentStageMeta.label} · Click stage or use controls below`
            : "Overview Mode · Click any 3D node to inspect stage"}
        </div>

        {/* Collapsible Bottom Dock — Zero backdrop-blur over WebGL */}
        <div className="absolute bottom-3 left-3 right-3 sm:left-4 sm:right-4 rounded-xl bg-[#FFFDF7]/96 border border-[#CBE0B9]">
          <div className="px-4 py-2.5 flex items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-1.5">
              <button
                type="button"
                onClick={() => selectStage("overview")}
                className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs font-medium transition-colors cursor-pointer ${
                  activeStage === "overview"
                    ? "bg-[#9BC585] text-[#142617] font-semibold"
                    : "text-[#354B3A] hover:bg-[#E8F2DF]"
                }`}
              >
                <RotateCcw className="w-3 h-3" />
                <span>Overview</span>
              </button>
              {PIPELINE_STAGES.map((stage) => (
                <button
                  key={stage.id}
                  type="button"
                  onClick={() => selectStage(stage.id)}
                  className={`px-2.5 py-1.5 rounded-md text-xs font-medium transition-colors cursor-pointer ${
                    activeStage === stage.id
                      ? "bg-[#9BC585] text-[#142617] font-semibold"
                      : "text-[#354B3A] hover:bg-[#E8F2DF]"
                  }`}
                >
                  {stage.label}
                </button>
              ))}
            </div>

            <button
              type="button"
              onClick={() => setDockCollapsed((c) => !c)}
              aria-label={dockCollapsed ? "Expand pipeline details" : "Collapse pipeline details"}
              className="p-1.5 rounded-md text-[#4C6150] hover:text-[#1B2B20] hover:bg-[#E8F2DF] shrink-0 cursor-pointer"
            >
              {dockCollapsed ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </button>
          </div>

          {!dockCollapsed && (
            <div className="px-4 pb-3 pt-1.5 border-t border-[#DCEAD0] flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
              <p className="text-[#354B3A] leading-relaxed max-w-3xl">
                {currentStageMeta
                  ? currentStageMeta.summary
                  : "Watch source code pass through untrusted archive isolation, deterministic Python AST + Semgrep scanning, weighted risk scoring, and Gemini remediation synthesis."}
              </p>
              <span className="font-mono text-[11px] text-[#3D6A39] font-medium shrink-0">
                {currentStageMeta
                  ? currentStageMeta.techSpec
                  : "4 Deterministic Stages · Zero Code Execution"}
              </span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
