#!/usr/bin/env python3
"""Immutable, source-hashed AWINIC R3 candidate from VEUX run 38131689108.

Files are extracted into RUNNER_TEMP only.  No repository changes.  This
is intentionally the same two-ALSA-getter patch proven in the run's RESULT.
"""
import base64
import hashlib
import json
from pathlib import Path
import re
import zlib

FILES_SHA256 = {'awinic_preflight.py': '6261dd6b6a48c5b28db6ce5271a30e792cb5a060dd354e62ed45b324110a2f9c', 'awinic_candidate.py': 'f4c98b3ae5f254a3996ee9f493cd9ead81a3ce6d43705f25dbf918d20de1d486', 'inject_worker.py': '0216c198b5c982722e8c63b1053b0be8c8d48a957c4cbba3d7dc26afadd3b011', 'test_awinic_candidate.py': '4adcb983e08291f2aa2a818316a57a1a0df50376c2a6780e9f54bc42cc44584f', 'VEUX_AWINIC_R2_GETTER_CANDIDATE.patch': '5c00ebcf5ceb1f9e2c8988a16d538e0048f7b4bb28298de875d6b4f0e854e7a2'}
PAYLOAD_B85 = (
    'c-qZ<S(EBWljVP@*KX^UL{i_?nDqmY2oOtxKnr>)LsB9ZNl=$njLm<a;}M|+P%gKsx@R8J?#)aQip7`X9>+cZ_it9)bpB}Ay-~0AhoSt@Y0qYD<BwKj'
    '^xAuE%-a94UmX3_Z~yDJ!Bjf-I_-1Nu{Mitb2V2E=ec8T7xoYQJ37x(b>k^UG_MWuz5nv|s=vIq)Kzc`Uxvx*We^Yh{q*p&*XjMOF(&OsIGBaXD81Z<'
    ')5g!Y*LiL5+Pn7J%|>h8R9ovtzt<f}bH~`v)8^hwCSg97rY5dqEd6A)bnTa&Uo+Cc9!Yrq<Z9~AxuTweu737fjXxL4=<Fp%>M554#?&94-2|O0#<)hF'
    'r7Cm#D!bFhpZI<DnLXz6uhv@97j_+=(W9W%P<t&|o0@fdVqVzq0y{bdufx=-VU8Hz)AF%Y>^^%Ye{V;tIoO*ZjyCkJxf3kij-|X^c1M~YeeWyvty9B3'
    '%3>d7RqD0&{Qqf#_C{~nG!EwJG|ygaN%Vh=vvCyl;-~du4>U1Gx+?9<_Fs2<fjPashUt4Z4Eu5M|M6rOwkFXkVDpeKo>GqjEuYib?+#BGbL-lprK`{!'
    'FkWn|f=+wKe?Ht}T_LSMTW9Z8D$cPb{To|vr%ij*A56CAffB{N)~b+|S^YxubZza}pYpTtv0gq7AJb6+n%ByWt)*wH+W_b3DAuXp)*MI1t0j4CXx7k}'
    'UP3({Nq&4?2C;SsY;(`{eG={6bz?{4_9yiHRxif3Qh$9npRMc6551PY^=r+g=ZunG2hYT6I%qXh*O{ogJz0zY^YNLC<T7;}C+^DYTG1ee+;l9+a__|F'
    'V|hbO3dhst2Iq8eYWz7i#`MQ|Ic-K>cNF!yhkpOEJ@>=i&lY5;rx`nU+C2Mllt4~bUaLv^Az|DQa#))?(T&M&*GeHP+g>MF;^&Dct0{CT^46EobzJ=0'
    'T)Bx6`S`cBKIpyHF7#{GX0BK_UvXuO+cdUjh<#eQt(S1(xaWlpnV&Yd3um;MJ37vMB7WbL799<;HCkcZwbxNMi?mr=bfSYh5%cb{dACiu5&C#`(Q5Af'
    'w0ZJsVvO!KbTMbFiS~GfbF23{kl)(m)N30vv(>C&%~<CUvY=yMEXd<(<;6jS`OzMQ{q>K2uMx?G>`VV9&i+I??b-p>Tj%;}9WD;(?Bo7y4v<Zz2RM6o'
    'iO<DeS}7AJFKyoNo@j1M2h8V&^+9$=IGaf*-n;J44qVo266OZ|u!T*C)a^X>cV+z`86314>yqu`bBZ<WsTu0_b=zBCFwRzo9RI>Pg$;nr2abN?b_#ZP'
    '+idh&Qhm7b55rqK?BBLm*l2t;8xzcRNj71PHPU(6!;sm<+<vUM9jF;EO#fiN{lwY?t>(>(jb+Ie!_FLGN9xc;^)R44aPFUl9X()-gKNu~u7-X5KKl&x'
    'G<+w$Alu7z4SLf!8fNrnZM7lO8OI{OaT`V|$zfUV>Ddc^CVy{szWcdiGCRo5gq^)OqZ;!WH%}QYGrI?W@TahK-?Ep*9$dv3!(C}#xV<dTNyr%NfARlU'
    'iJdpuD2#FRJL-x2VKyhP*1Qek%pWk@xb+iv3tzhGclgh_3}!MtC!152XZrbN&Yt16XJOC7e&Huz!*V&_lRd&%;tcYA6h1+VT}wS;4`i=nF@HU=f~BRc'
    'mNQdrTjo`Re8=~GbIa^J&X#-uv!nbSTfL+!k)QM`b;a$DE{-DK+_Z^j^s^89Mshx$TBIxN|3U{b-Uo6qiPZldyG^$52W&R%BHlMww9TSpZ3m_{G^O^j'
    '(BGzzb&bgZ>|%aC;!K6@4)=p~<Ie$;n?gTuhGH-4&;cXDS)>CofBV)9$bY)By7D@~In!4*-(r9FUhJOl&OFA?v46d|ekN>2Hrj(v4IEk<WI<6=*nRQd'
    '-acPHvl)$&Pc_zVwf!vCDCRV`^#gEH<aOXv$xhIj{lYrwoMHbVLx$|fFX8YN-*=_{Z~y+=;<8TG{vZA#3D&{l`2HXJ6acxG0vtP|bfD;aZ;cI3=Aqw>'
    ';LOz1@UmO?*1Bz2*1Y#>o<^;gbab1*5eC?-XamOqC(9h@W^UI3hzSgt;mfWy!-ip89iUG>z<~UOqdfFF?rLFQaOl^wuRsXGUEk`g$O+Qd3QE5QxIDNm'
    '_8B<#9SO|I?L?%^5kLlWmgIni;X2Np<^>z0Fh>j{Jy$|F%ZLo%4s(Lg4*S@=!~3);1<H?bVqRyHX$dgID&}q7dY$Mb9CVC>zAZZBd}XYM9I|#;ID0tR'
    '=1&*S!?mGQii!;;K_IYZo>~zHB{;ay&_)v`AhrP@0!I{^A=YriT2crE0Er&C08q?XvV+25#(o%dRuKURICXkg0%LM;F=wH4H|!VAqt{>9Ft#-vYh0~-'
    'Wp!BC<)7_guwP2wtG8C{LZKxNIy%?=e2oADK-x!;VbaeU`}}*%wfJmzv<ncBc;(;MthEn?WgzKN{2coP!|d+ir2DNnA|stLgRVqy$fG4bgEe3GuCgKr'
    'ihXIuE$Fgg>2HR4Aw!gmrZ3W9)2oeIe&1|s=0t+g+-f6(KuRlMa_C5!gJ49T$m$f1u4`C^i7}QFNqaNeQF~$;+91JuasK*cKQXuJ*of4(i79Jj1oZ6l'
    'sXQH~^*?crC;hU+oS{r>IuA`=09^Gu>QBhq(O3NaTeu5*twu;r!Hdbcsz0-zv9GSaT98rDxFQ;ko_e+3PA|_@R$H^S`Z|@Y_S?FV^je3Iz%(3t_HM`='
    '0*Ux~p0BsR!+>DyX0FHpmp6WPb$Tux&F0y&Cm7Th$QNXKB=uX{KK2!k5qb<KgT04SV&}5+Tlu&b+6#8}t<{CV1+4>ee}(=*E>{;A{af}q1R?;L6TbFt'
    '<Ak*?{aSSNpfigUhuCT)o*e-+M<+K`Z|}AYnXDsdW}pAP*Yd+Y1ByMG!~St?ek0$5=pD`)G8gqJ0Aw~}RC8bDHv$*^*{;v_yTby(13nKufoya~@;qrm'
    '#z&D~8=e3rPJQf^Uz_YaTe~n|217nq<ZXYt&BojW3LAgrcWE97rfQbtci}iK3KUHMS|fVzPE@O_!{E~AS1|eq)qp<w3j6)uvn|-Ui8`7!O6$sGs65Yl'
    'rt1tKVgD&uKJd?!zSvw>Si3<^c29Dmr_FdycF~?>d&vP;#{$ruoN&&thk9zK(sek4Lyx3=3$_)uCWfwEeAqJVK{`(_q1VyYuwR&a0FZvjWxI6t2RNa~'
    '!@k17XZi_e6=b$ICEM#d!JR!MSwPU5xU(JR+rZghSM%69<g!)MH_)dV?8?uQ?A`o$xE~~X1U)<iG0EB``yG3>Kc#)cK6c%RWSj4if#4|M$qD9|qYVH;'
    'yg(q#*V#CeeHlbX)7%D{m46QJ0Z4|8+X2w01laE1UEli%f?WFw`w=MsauNa`K1ay-LSX^rq3~@0T<}wV$4s(yV$Ct;P3Iey-vM8+oF^=J+g0e>fq-K6'
    '+5VL6{l#6^HCt<H6WP!VO&!nL#?q9c1q<wJ7C`Xo0su@h08o+x)WSb^NBj4<m|I!DF?O;b5KT5DQibh#djACW3+GSoRV{Nn(i}-2&ZOS6+zR>NKFoTV'
    'v!s(wiJvHdukW?B8f*e3w{Fn0l!6XJAwR9d*Y}tm<Y&ZfH|^h}{StDq<lkFMC*7XNS0lJk+$ro(672E*C4$8x);NJLc%5q8_CxRQ#s?^)#0`Pi3$Vpz'
    'LHcQHTSw9B@MX7th0F|FjUSL}fY25H3<3=nWK0`B;J>cJP2)0baa%cG2mbqO<D!cIe__7}e1f2n{+(X>_xslfb=Xhx^@{?_gbW~eEChXiW?y!0w@35#'
    '0Ge@Ly%7HbyEX6TG=M#20n#)~U{B-0EKDHZH`oH~(G~JhT4Vmz+`|SR1_>o1b;+;Me!`Hn{NrE>-wFGnr-z^Yw1Kgpeoyvpwe{Cbc04_m@R{ankTQEk'
    'vSdyy9sU|Nx8-Au1NP_#^Mih8ezMxy)Q~LGsoIyCkO`a%Fw}+Q9U%DN)tC*Ub?@{PevixKrq@Ow8e3^DOE_l+-dlz21qkGUMMJ`mUUv&yXeqE|l)$(l'
    '2->)|wFM?UQ<4Z@d$JL8X2)TBYt8yV*iGOYO5{KX<%=7`Mo;Ue%kk67Pog&M3xYjhr0tGlpy*{h4e&1OWngDIA*aJsO32URos#D?elP2n&oHolekXgU'
    '(V9ZoFFE(y!Y3ZcM>4%Bp1-$)jpyeHD`D-BuljMJ7<-?|Htc_5+;Tq%eTL769;!dZ&-Uf{5uW#A^Ayx{$cvTRx!j)I%@bI~9?6IkcDe%jYWd__;DejM'
    '==6WcnmyX#nV%$YLJu;ZeWN%7nEmCK#uRb@|3f}sE%v7@|5-AS5@OljRNHN_e_4DH3R_9?vv+aM*}4b$n0N0fVVnRqc#@EB5pu}>Kd^fI->FQ&@@A2K'
    'dkx<lJF|I^|5~seJBYPnW9`+#yK^o1i;YJ~m+6y@497DmEY{mdN_r&T(X7p}M;teEzfkCE$#&#E{TuJdVz2BB$R5B>&TEvIhAac`&^!1#hM~!I|2cN+'
    'P@>p~SPT<u>HD-ncu}HrgnfbUgx_K~=}0jyB>*DACmvg4kM`%{r7sVdq|TGHmb!k&Irs?t?_}Tu400!D-2aNtk+0A31|NIcJVGCje1CJlKymQdCHd_h'
    '$~H8CKS?O&m<wDmu(P<G?2cTH-IFrT(QmsD@yc|zwT6ST?Pvv=9mTkhwmtiuwRB+{agNX>eVLsfjY;<2Y)5Yxx9!NIv1RG6hQ;EeR`q+V{PRu?XFlu6'
    'qqYA##i#S>3V7DV8JYXCY)~SOV)u&Yv-7yaFqx03c>clHUy5gyIwiGe5ALwW!y2H&&{bd{hb|T35&VvN@>7hj9bZ^-s)PBjn=dQ}k=vC~@X=nl3S@Lj'
    'pBMJI6|i{Ag$yBfU%BOH+7y$HqQ^N={6Kh_&LfX!T0xdqp*3}&12>ni7qOLm1}26-{BTV8X7$3}*$O_*wY(7~O8G?y_ZcSTgCsgH$^&^Mo6tSjf1xvy'
    'i2LyK8cVwJIHL6<G&LRO!R2{^XPnEh7vi8B^b)o)0!AL*$FqFQ%9s}Tb48a91)hfPvb;vFb6bkJfjd)RX~-sv7k7&U@yfcs4S)ln|3WXB-ANIrzz#(v'
    '--@`2@ZGDFLhrGrz{eh!bea<WVKT7-eYTBW9l3XNBy~D9>3eO+@wmR6nDw?J!N(&~Fe7y~k<^JXlOdO*8TR{iCdt6^SKxPwDJK8wwGGX}c+flc%-F1t'
    '$=|y1RrZxo#Jq*gVwY)aVPnEPUKc(ug6*<^$tODz=ZP5d0(_*V3yjO<l454;Va+-O_#NeuJZ1hXF(~XG{7{;`cN^xmDt)%EV*HTo8~i6^Sd9nFMu#Ok'
    '5iq+4nV=k`=_ginpU)^TqZqG<r!qhCaje2(N0QSr#;u6QSp1cZ_v{b259IH6z1$yIDz{}kexsaFQi-1x_^-H*{cLU_PuzFqK9J_^QcjN9OOaclHB`lo'
    '6pPDVcS80|0>;REY9f4=I5)0e6q^P1Rm%39U)~T#_V>*93j0+NOXl{8E>?j@6S{1nGa>&BJebc7a+Or=zmT^~kM^D&ELjeX=M2cM<7fVfUA$_UuMYPW'
    'YrgyJnB_n2_5i=v5}ZYT2Fyn&x{Ucty>@h*!`}{SncO#F0|REqs@4M=bgRs3WVoN{(>5F+1`|4$kbLR#sE$2|ylEY{fZ{WOql8UzSx!>FA@;!h>6}JU'
    't~1>KoaVM1F&{){RZTt-c=G;tL6`q7&(F0Uu^n(*GKz4Hz$>d%Ps9K8rqR2j4Szb_;ZM6}n2vS5^?9tw=RtAd+TV?DdtcX%?@o6V^waHs_FsSe?zHL~'
    '#8JydGTDz)!nn=bJLNtrWM9Zrljos_p)33hlfO>=jPnq_lgH?UPXk+nUCwo8Mq|6SbfR2hp1Wl^h5}>GZ0#p-nY4hv$Z=?^Deg0x&{yLUK!$y~<Xy|;'
    'H#RumHNWf!K47*UxRPBkbN@=di4$j<%tmK1r?5k(z-h93kv@y(j}hcJlf{I7Uig??r}JE9h7){cwHj_rWo$=BS5|j(2QkK-U%$&uav8H!x_2o)>o9#{'
    'XE2DZ({tWoTcP9pi!R8Zx6#-Xn1bWjqgONbp7N6AT1&ZAe%}B+oKW1~7kSKYV1ewjlsDUB9W1tBzJbd@{`=4K+jqnh;oF-`NAG+P!wGpT06V^t`uuL@'
    '<aVv24;&)Sk>wNpga`vx-M`7g2jRTnW4&ae4%gd|axPBirEHU#ZMD;&xMSH26GrF|zV34jF&fXTrao%}gVWuKrVgiOeL%UssVO%N$yCj@HZyOB&}dus'
    ')EsG!+-#ciP@Qdmkj}+k*SalU`Fu<B;slFq4p|<$>q4KR_}x-3fvq2~$B6NP7rNFO`@G3*N4F`@<LjP?Us<jrf97HBWcLNuLX4qpfwd?Hx}VpKCC|mI'
    '_`9I@WG~IFHM7jCIf&UgJlV)nj*!ir`ISc>Ca|DW>)i-1z1O7Yynl{y2**!$x>E9~C7dDj{?VUYV1s^=&wxCI3&hS$XD5$3S?yy9vjV4Y5O)!A=sWMr'
    'F~4{=!~GR`xC~oSK6j)ej->lh*ijk!G@?7q%3L$ok!&wAy9x|IcOdPfW^U`+EL)GTZDMX8#WiL8@HEdVy!Qe2sC+iFN!k7j8}zOBu=(36i}4;lUxjn_'
    '9$nsdqH=zG<8`#XH}xyz>Tyki`~{2<*!2yI&yrz=#XMbkBr55QWWe&cN;Qc|m!+zCX1JS(Eqmw|;j;U8es%5zW-Z@4WU+hl7w;SjY|dimPvsE%eA(e$'
    'CpWPU9=qEg!GH7;`_?$V+3lkn$^RN{43*^_1=e23(!Sbv@!b1@$hzxBd3|C{g>Pm1{Rw9O(BIy#HOoU3pJTb5dp|DTRq3Z8kNb*ukuM`s$sT7)cw-9;'
    'LYQMVZ3{g6rA~8<Tgshq-F~uz&(BrOC%0+h`P?4U`6~R}3SZkK!X(*>rX@vh@KZ~3gD=f$&DzoH#4_}mR9_mBW|rdNwqd#YM6#CL$H{Lq_&J6j;P$4b'
    '`u2<Q@P8EqoBhxCWwZ`g$8QsCriQ7t2YBgB+dh$GXn_zY7{Xu|2%%$_Y?`ZCR`?Ye=hO=KHVc-av~;;Z0JR^xGL+%Z9zY7l#peNd+W^PRX*MBHFhB`i'
    ';4xAQ0<rpu0CMTV?!bOWfSHoZ9gKb1XAX&ibBPgph!N`ajt~O6gx=E_ZYPS}HM_7{-6vm(RhwUygq*bV5>6fZj7oEV!};}z@r;1AUIOS@V(i916J1`}'
    '*F!dUk%T_;1a6cNV~Q?>MDRrWWBCfZxb9=G>)6|~w}I2$T9&P;C85%nrff8=HUX$6&ddd13VK$netDlZjsqu4(l*YV-Ak9pcU1tPlMB0a%r5u_ESVUd'
    'gU*k0)jKI+V709&09$jmHFTp5L7vw6x*Cs!AT4z<o{wOwM8aX99%r;J{p^hMiV0}*iv>m^3iEL|@G233^zwL6PMrjQ10ZoL|NPw<mOjJImH}hz@kd6T'
    '6My1~G}>(IL)%@$;9T9;;ccWC@!QO=k6z8I+nLu!0C@A8e|?)p(L8Qnhb_OKB~%!(r$!f^D+ZnhiY7zO&iEHVZ+I3=(c2(*dSR(jqrTBE`>Cy!NJ1Yu'
    '&dc8X{5d0g?t_bas*sppMze`j0OKNI<tYc2Afu`huOI=@r7TNi;`jF#gRusKXohA&mmUb<OwP=QG3-ptXgDxO!<jtNj8{R*D8|l7LggeqIf_2l?{ZR('
    '1Nwq&c47`?x?1b(b3HLOBd!P{10yEwOTi!`ve2dYkP}#lA-@Iy-ytx{5+b`28A^h|KlEFBx>QlJORpJ$km)^%>5h<=)&c79en(G;xydfK>`~37L}bT$'
    '310KyY6H7P>xvvjl>-DF<=?SOx0@`0a7AMAyJViuJb5S5U(NM~nyhl$evMq5$9t`j6L;vs9k%JxZ$;kQW+>CM<zO;%HuM~9p&S&1sRD$pR~Z<B4`CM*'
    '#TmlZP}0Mr%b`*NCJPoQ=@YbgVuJxBR^8By`eGdXyfU%k<2?Oz@AoM|)2Rpj=z4Ox!#}^SI%@i5cDvJx*f{TLL2>{{ywUl3l(Z*S^t29J0>4IyI!?f#'
    'i@MXGxYXZ&M66kKBKRYoL>*R;X8;IKbDnUZgaiTblq#|CeMY!qNvRUaC!u5!04tj(UE*Y<iGoxCAHv8mbqX#Y$7O*5^W#*-VasdifQ)q@m?|!bsQM$I'
    '3vWlS57x~l5qbdl4|y<{Hp#9X@cR{)0RU*HcekDeyL`2nt)_8s{=fi~{GzXRo(LXL5(j4v96`8YKPdDcAdFp7q?}y9pSP9OKIo2!qy}tIhe6r??qvJJ'
    'unQ$i8Vm$hCI6Pz_0)g;p+au%t1G%!-(J&YHQ^q4MQ4sRRgvos9tZnkjjGgZ*NKQg7X`AHFot#lZ1nrn8Dq@KL|zASLCM$7)7m)ct^@FG*Aud9ZYz8u'
    'G77mk@Nq7sz0xDt+0z?+PLp!mOC%M-GW`+`BhqORWaYN*%ygj!9EWk{_T|LnNnscLa?qI{--=7ABYT$PB*I*uJzLt(A7Kyr;j!d({R}Lzf!(1bm$<+z'
    'T?hbU0B0>dmZUkBZP0nZF50(ykyNJtv&3p&qsp{;b7tavG$Z@}-gz8z`ZVV8uZ{`*n7XW@A+Io@B<qIAx?XpCV1Y%=WisT&Kf)}aCgM*3y#|Jk1de1E'
    'nr?nc`I6gaA|7P+j^qqB;Vkx+VfB8e4S4`w)_zbTapxeYpfBiTjV?srr+h8%Wd9jq4&wv&_q!utnflF9=yQy884<2?=~4;j;mhi=pZmg`ut7GJl3+4q'
    'U65lR=V*9uu@-RI&*mVo!NYU&%|56~Zau9zlbZ*-n(b$gd=_k%i`b(`!0Tt1;)cTJ=leBZU(a60SVLy(beYoEejJ?iim?OnGZsJmz5t*uWbs<;%SRUx'
    '9rZw@8MnJ7Tml<GL1|tA!Y(uBwhK%k;~DFKU_J7(VD`2BQ4%{T>1AnsBB>1dbCo(HlN6+shk3Pvud0X=F&?cu-v>$n6vYNa&WC;Lu;fJq87h$m9|=7y'
    'k;$u5YNN_((lT+ekdqHDSZ>)RKd>Qu)-_A2uU&pt83`b{BT<zwm0rsUtd(o!$;(E9NI+EL_~HVe5<m4QP}sSCct-PSL6F72Br|*AGjoE*hv!p_U&u}E'
    'FIFF=U&~WgB~`+H<?5(4-uaVVxP7pf#d!gr)-0C%FIPV5Wh|uRd4sYa0~UZ?ggzD(rv8(^v(pvBMReg$ILlM6Tl=O5{ppo|k9qL#w@-3I1uz1q9_Vue'
    '+T*m)>yK>vps<UF!e>xEG$XtdW_Z~Z#RA%8Y!`9yU`zkEj&#vx0*^sY(ms(ulu^1sOhCA6Y^l%<b>qlCvNf-O`B!cS_JLvxteMF`ia1{Qcs;#J@4!!E'
    'i^a}|T-WTZfZ)0V2EL4^!MJpR#NuQ4HBq1wop{CaV{W5FFn1c*b7Si$#X1;4*AYc8-=D_>a)el&d`c6TGs0Zx-Gn{nrT6KHf0JqbL=3%A0uwP=B|(}!'
    'o7S^Avx_vIQ$qa5FCTajLB(_5Dk#Z`_f`0X_G5U;iom{jcSiaq!hb$K)<oEm$aNg&)kbyCrpwhsMnp}@1r1!T@Xn8j8z00Y^x6JQQVnZ0G0c%kd6AiP'
    'B{H0DZ_UG9Vp{=zofbCgSytSS$Qn-s|LncrBj1T+Y(W$`yE&1QCt-n~us3y*pYFoJ-m<vAk@V%JKHJtQ_c5Ev)|3*hlkIgpS>KcJ^ZgTN_DIHfKI0Pk'
    'o`|8X#&sC|xC~##WlX1+INk6<IfmRf<iy##M0b`K#Cg;c=t)5+>0l1<-(%}|fGy$#`_4;=z#o?I^cFa%dB8rC{IEIWov=aI(<dbQgmn~wJ?&f4lMZF?'
    'XFftZBv}U&Jv~+u==-uDcWV-ldt&RwClW9#G%N_REGOA5E^7WE;(8{hM^PMgB;P`WU)c8pt>d9kjxHrtL5_;a?iaBg|H??QV~0I^&T@QJ&wPixE-w3*'
    'o^rTP;&UILk&B+l>r7Yf{Ht;HluJ%92X17ARdk+ZqBh~;M_W`bQh{&e1nyV`#<`yh&v|9U?SjDmH^$8E#@P9gU|se6ZS05(`za%_9SR)qy*cZtJpG^8'
    '8~&avD=vJn?d8I;{eTw`&_$B;5pMdBkPVy3iH$*4h!;YxR&&<5Lp^vMow@>5UOJMmge?$$>uK-RvBL}VN+j<iV$T)VU&2|8bV6}!4F8xcx|8BPU474R'
    '$bC_4$1<-&r@{uCnywk!t8Pdu6ZnA092H}g$)$mAY1}uAr~c26{Klta$fMqbF8el8(pMgG$Qx7P1$$3LtWN~ktRUEwR!v4a!hEWVVuf7o2k|O;CoH27'
    '`L{&uEB36z?p3~;UtvSPF(%#NMN3Ny#swL7w8XrdGuUY374N9=0?$m(%A^x<k;%_b62u5i&B?oTDT(u#TINe7DTngsRHW?4D#PW#uPSWz67ekM(Uyok'
    'vV4*RyZ(EQmBl(B(;F8UxYt@ud4ZIi6*C`tZFQFaU$cmCM4dG>-f=?Md?&omM~HpldT+fzzZu?z%-0G31%$hkd;3oW$U#g6N0Z$Uc;UBy|81RY-u>er'
    'm)+0p`_FIRs*XL@KPQOb5h?2$QMQwpsjDf=s8V^lZNTdD-ZG3@sc;IcPrZ1sGLL#(VAYJ4r|FZ~tS1euo>Y{Dy!1usKeuw!*1%TfoK6NW3y)eSE92R8'
    't2(6YD6GrNsj4K>b1W&(5VO)<>%_{?u$ESQT?y)9)~bL?K*&lHg@k1}i#6mC1S?w^tefSi<8?aCJRh|vxbGv>!|we`%Ya-9!*ZK|=vG8zflR%UL`gka'
    'K%!s$6J_<zOx6di{GZSzH0HCLE>^D7(TIY9{Txxr5oP8NMLUKIP^3#)ibL-qA}pdwu@?T>JR5LdI@`DocxeDpJTE-UK-7N!_q!W+SODxhWi(fFM5Y*r'
    'vQBiHzTu^Yd6a{Q6P~G+m97+-8Fs7Hy08+5IS`EB<+4L`!8baycpqh1Zy;ahecq?co7_mID{h$>RgslNQwg_XR+O_{!r`>oSIE?#l=16#C;6EMBJ;?{'
    'uz<dZQi5^sOGb+J5wRt|YwE>y^jP$HTZuj}{AZn)<gb6Wo<Ez@_Y_w0wx?2DcPjeLa2h3*UmQx~7l`>=YwG1UZVT!c=U@(WgTQI3f`%x+0mYv<b<y8r'
    'ZR>wvj4wZv(LZ6oZaD?gx}I1+t#ZW2vxjLA^K8J}rqXV@ks93!d10CEoJ#Ic`5j~hvUoRE3BlFo_Av^a#wok?aB{@M5oXphV30rCTxKOA+4{H+3QB!J'
    'Wn{gGsAOR7FrDO7KTFNZ6Lxti(LX=0<gSb?EztvWs%Swc%}em&&)YJ5HtusN4J%m{a$nC&C!CyW8FJcw)|#NA#N$_FJ4em*ZbYboqG6w{i=*T;bjql#'
    'f$DF%%=$z<?=dfrfKMp)mbH6$mdEvdMwZUo@bp@+f}fLpP0cByltG#Ujr(c9GOpRY21!mm7Igg8LwQmJo$r10PGJ{@&vUOnyF-P1lC9^yURDKlj=l4~'
    '1W|b^!8sRghB!@BV1pt%m(yBtRygBvr(9AlOGQM#J!aTo%<UU16|S=XA7@foW`i;?#Pm6Fmc^Fc8V+ywH!g^hs07$%S@D9EA`7Nf?lYWPhNFl@)tpjt'
    '%8`Syxjj-DTZd3Dm8zMtv9u_vkcbK8>a(`_RE8ydu2gO>lFu_bTpeotl2OVT$`s6uNP6_MUuH1#cT$_2B1^dA<)L{bC$hUaE%jVvIiGy{-zrsPpTqYV'
    'b}ae&Y^;30DC<(b$<Lx)jwSM}+sSo&(p`ZeCM>(3M+!CSPdQ;3{$8sM`=e5si<qlbqken=k7jcH5oPGR;`V_(e}6N;ZUKs0i`-s5>2R22Sc{#@L+0{+'
    '4mxWQfrx{$28ahHqKv9>?&Y-6;nCa-bAQ@f=Qkt|Hy4i?HmohS#7%WGD}j9|5B)nW7OG23X?>q&0c6!QOnH*)(uPxCD`>MV{9G&PTt@p<c^jXqh?veA'
    'eued1q_#O<NAHNVN2XTb^->g1%!-_$I7l*T@QUP**cVx*^&8Q5eeB4(X13L(CF?rgIU8G%W~Tn(k;dDCEcG;%w~DdUCCj$9K8}>jcACX;>s(JTr%~hs'
    'gY@s?l!u5JHX<=r?`>fVIp&PsU+?Uu*sm4KW+9s14|sN8W%i1(zo<X&w#wFuGBsI)zDxaAMAhMc5iR-nemMT|mz)2M-PmQhZMu{7)^gEAA+{J%8xiiA'
    'M-3y%za3a(7REy*%hRRey3w9EsDvQtuHv0H+qw;ixf*^RMKWy+e}$)7;+z(|RJz-uJNX;&=1N@Il1I*SYb=l9cji^k-8DJnIqvAC^qwr*S{6~b#u^Lq'
    'Lh@_m!?WgmURj?r4r%Hq_dL9hI$y2?uY<f#eG7D#-#_<S`%<^-3+p8QYu#n{)D4$)9jAL@>dMMH-QINzrDuMr>!}%i)%CRbw>uRV$b~wY?$y@XPxQ+^'
    'ZwzQ@A>$b9Y4DGC@%`oQ>IvrC$vgPwdw#bsGqEOy>c8TqteO@qy{)OEnPgZ%MUVyet}83+2-^MIol?WQ&dG_?C%J7!A`i?PG(Pb7%2}nA;wjOVI+~Zx'
    '>-v^9iT_6tH+g~l%*-eh1&@#1z>(l8RE}5sXgrdE>hTP!wb%u*x_4XK@I5WK4R5nUNE}7T678*SY$MHJ4Vbbu*YoJN-}1wMv`f2ur6MiJENgJavsTkE'
    '`Df+g$TA%|A<=L@1F{}szs57h5r%Cp>>9iCLlg@H=86u?TGqr9Kbs34JBxNAA4skL*j$ijC0Nt4obUGw*^Q@$k^Hmby;%hDWwegp2`*k|_|yQAqaqPi'
    'w(5Cfiwq@KM0;5TDk8c&ugnXvr<c28)okwwneqtFT4oI_`o-KHIa^twZ@wOe{HdV~i#)KlZdUmFJpZgQ$76=!;T@uAS48!quA~(cw|I2xwO5E-43qiz'
    'bXEA%R-OH9qG-1gFQ0Q;>Gzsi6iZ{DD4OI2@DIF2_A{XK8p)5L`3~_;SDzLG>Nj^gdY#wbW?DQ4k{sHT+wc}_-OaZ4Hk-&p+lWWEVC8m(wc%`AcWr$&'
    'oHZUeQ=`c1%ulpNs#!7|O`gLZP_vE?xf!B<BX3yP;q?kGL+@1BZPXpQBi2+_;{ZR6$SycJN`_olH~5J7fuqQNhKTgWGH-3VKhzF=YTg!?#;Wm#N2IeX'
    '>YL5$K;Y?{t*?ji<m$f8rQyw3zjb=}nHG(1KGrjNncwti^t#%NX2bfBq7xzWTz@F4G?p1}ks4?Sj0V|f=s2r&SQ7rBOrO_{mIW8~7uHkN@QBu!<af>D'
    'uF@<c{{vx&sp;y5Ik}4noDcbkr7!L9Ni&P!5o<{tYXw2&`64RCzVJqXnkw#Tfqx@v8p^OA<L6fFM-9>2?or-MR=;E2`kF4o7gICY>^|-H=f<#K?^CZ0'
    'pVE#xQy|Q82A>MIg^#SiAsQ-u|MEt%RI1adUN>cgqb;2w<oE`gCkp5Fh)2JSuS{!uw5Py5b=IJze1>J8_KO|oMN@1wJHvlHWOl>n<~QH+mD8_%<=@7t'
    '54MN#f*x((ltpvSaQ9TxHQV1c8O-cq`RoSlFN9E`_FZ(|udvHG$Bk}6Si|uQe_CJ5GJglw_@TW0O}q&i{itEc2mIq-I~&e{{agA;J|eH*C@^7Z-!IhM'
    '?Ciz&S&S;%TfUXfGotJ-66Cjcm41^NR*&sce7UaY**a4?YBNM$GwEgjiLceYbt%jC#jS*%Ua8sj_s4tAygy+y%K8r~@Y3MEc|5yq`NsP*>_E@mar}8!'
    'ye@b{ls&v$zk>y6kE^noPqzUr*wNSaug|TjA$__%46F5a3;ahp6=DM9c?L%*Wg#P#ag==et1KP$#+s~D$d2Iu-TP^c-?+o4-)HW5#-3uQ12Ah!_L;q}'
    'waV+Q$yVn#!P;nGAm+E)>f4w0r;vBViX-f|zI35?UYGvr46lLzz_)yAKP~Pza(%ta!&K|Zy<e)lRVLnFmd&TX<YlEU;*)AD$Z=A}({=I&lNk@M(zbH$'
    '+N)IA?3$gK#<@Lx%B8jHk4>&K4lQpubkCvt2$LNI9y{FeWs?yx5hT{woi(BRvN?2_*ZK|neb*%VXSqQhVcYDl?&;~V)L_&IKGWG*tV&bF82X1bE!T`Y'
    'TqTp-ugQq_vcL9Xsd>{)eE%n}Yoh!f%aO|bGt`jvGt5`yBnMHc-+^gRBOT~0@BzPFqGq&5|1Kk(#b@d{c$G!ND?HQM{;Nke`o{T;gS6C;HEmuvr%)|7'
    'W_=!$^ZAK&a`NoscH#7hJI9z#SraPYo=bl7kZ~3}y+ru6dpsl7O!hqE?&?gp56K(<H-Asn=RWtpcbWD5Tg+r%*mCYu^jrQ1YLY=kjQeT4_soes%-31d'
    '8~^KZc!Qs;8QGcg!h?w2W_I$rm6+e~h$e#-_M#5k{R8tCoPFi^7h{Rf_9{#UHIg4c+ppX3l^R0(XKE;3YRp{Li&DcbL-=ABc1^uu9((%337`0vZ}H1N'
    'YJ6V78K-CVZ}hBkP<5r9^fz;<B35FIi?MC&$;M|nmhse=2b;-hxbY>}g6if{Gtmd&scGIdYm}A$0g!UDr@VpPSIvC7pEg2Lzuz3W;w$H>BA(Cdo$I%;'
    '_19wHUs%gi)1$FtoEPb}XyDA4b^7D)ADbGf0kH(XT<1e0p^Z%PaA3_dfu-pd&wm)R!seX6kdK^6likw7K5iC_!60NL`-`ozx+XiEJ@>KiYd*=)QzJ&c'
    'FXg6wYKDKG$6aOie`;7GYo--B(=VD5pQ~!}KESK-!U;?4DBhsYXMd!Mzn@~Ae2x|IjcDL^qngHy4F%lCasy7@6za=d0>gWyKQwi+N^z6Xp&GXlW81RE'
    'j;z0ee7PG#+?evSD*Yja*&!qu8Bc?ip6-;<ll;M_{(ojmN)3!lxkkZcoyou0NbR{^<gQuyP5!Kz+=mTeKh4kmKd>Di=-N%(oG+=t>w``CCv|R14T}5E'
    'vXD1?{MvpLe<Z5P?mRV9eX^5MGGF_Djy97+xsl}<KDEjo{925-|JqJe$4NOO8uO$-uEJ~qF_KshFzfDqz8Y(ESJHU8;`mroIb+LGm;Gs-VI|S1zsLjJ'
    '-}#^X?l$?g*eN>oTfw)m4XelPew{OU>chnAV$`wqQ7xr^pml#M9#T|dkBA1*z<^!jh3cywSuo?7lsK}=`n@>vkK_#)V!`V6sj)9-1Je1<V}||e<C$QY'
    '{Ga~|_A!lu'

)
MAX_JSON_BYTES = 120000


def extract(destination):
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise ValueError('AWINIC_DIR_ALREADY_EXISTS')
    if not destination.parent.is_dir() or destination.parent.is_symlink():
        raise ValueError('AWINIC_PARENT_UNSAFE')
    raw = zlib.decompress(base64.b85decode(PAYLOAD_B85))
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError('AWINIC_ARCHIVE_OVERSIZED')
    files = json.loads(raw)
    if set(files) != set(FILES_SHA256):
        raise ValueError('AWINIC_FILE_SET_CHANGED')
    # Verify everything before writing a single file.
    decoded = {}
    for name, encoded in files.items():
        if not re.fullmatch(r'[A-Za-z0-9_.-]+', name):
            raise ValueError('AWINIC_UNSAFE_NAME')
        data = base64.b64decode(encoded, validate=True)
        if hashlib.sha256(data).hexdigest() != FILES_SHA256[name]:
            raise ValueError('AWINIC_PAYLOAD_SHA256_MISMATCH: '+name)
        if name.endswith('.py'):
            compile(data, name, 'exec')
        decoded[name] = data
    destination.mkdir(mode=0o700)
    for name, data in decoded.items():
        (destination/name).write_bytes(data)
    return {name: hashlib.sha256(data).hexdigest() for name, data in decoded.items()}
