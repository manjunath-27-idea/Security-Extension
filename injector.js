/**
 * Security Extension - Application Layer Injector
 * Runs in MAIN world (document_start) to intercept fetch() and XMLHttpRequest.
 * 
 * Supports pattern-based payload checks and decoded payload scanning.
 */

(function () {
  'use strict';

  // ─── Behavioral Protection Engine ──────────────────────────────────────────
  let extensionSettings = { heuristicsEnabled: true, debuggerEnabled: false };

  window.addEventListener('__secext_sync_settings', (e) => {
    if (e.detail) {
      extensionSettings = { ...extensionSettings, ...e.detail };
    }
  });

  // Track genuine user interactions
  let lastUserInteraction = 0;
  ['click', 'keydown', 'mousedown', 'pointerdown', 'touchstart'].forEach(evt => {
    window.addEventListener(evt, () => {
      lastUserInteraction = Date.now();
    }, { capture: true, passive: true });
  });

  function hasRecentInteraction() {
    return (Date.now() - lastUserInteraction) < 2000;
  }

  // ─── Whitelist and Popup Blocker Override ───
  const WHITELISTED_DOMAINS = [
    'google.com', 'accounts.google.com', 'googleapis.com', 'recaptcha.net', 'hcaptcha.com',
    'facebook.com', 'm.facebook.com', 'twitter.com', 'x.com', 'github.com',
    'apple.com', 'microsoft.com', 'live.com', 'paypal.com', 'stripe.com',
    'okta.com', 'auth0.com', 'amazon.com', 'google-analytics.com',
    'linkedin.com', 'instagram.com'
  ];

  function isDomainWhitelisted(domain) {
    if (!domain) return true;
    return WHITELISTED_DOMAINS.some(d => domain === d || domain.endsWith('.' + d));
  }

  let lastClickedLinkHost = '';
  window.addEventListener('click', (e) => {
    lastUserInteraction = Date.now();
    const anchor = e.target.closest('a');
    if (anchor && anchor.href) {
      try {
        lastClickedLinkHost = new URL(anchor.href, window.location.href).hostname;
      } catch (err) {
        lastClickedLinkHost = '';
      }
    } else {
      lastClickedLinkHost = '';
    }
  }, { capture: true, passive: true });

  try {
    const originalOpen = window.open;
    window.open = function(url, name, specs) {
      let targetHost = '';
      try {
        if (url) targetHost = new URL(url, window.location.href).hostname;
      } catch (err) {}

      const isExternal = targetHost && targetHost !== window.location.hostname;
      if (extensionSettings.heuristicsEnabled && isExternal) {
        const isLegitLink = lastClickedLinkHost === targetHost || (Date.now() - lastUserInteraction < 1500 && lastClickedLinkHost);
        const isWhitelisted = isDomainWhitelisted(targetHost);

        if (!isLegitLink && !isWhitelisted) {
          reportBehavioralAlert('Popup Blocked', `Blocked popup window.open redirect to: ${targetHost}`);
          console.warn('[Security Extension] Blocked unauthorized window.open redirect to:', url);
          return null; // Cancel opening the popup
        }
      }
      return originalOpen.call(this, url, name, specs);
    };
  } catch (e) {
    console.warn('[Shield Heuristics] window.open override failed:', e);
  }

  function reportBehavioralAlert(type, desc) {
    window.dispatchEvent(
      new CustomEvent('__secext_behavioral_alert', {
        detail: { type, desc, timestamp: Date.now() }
      })
    );
  }

  // Hook Canvas Fingerprinting
  try {
    const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function(...args) {
      if (extensionSettings.heuristicsEnabled && !hasRecentInteraction()) {
        reportBehavioralAlert('Canvas Fingerprinting', 'Reading canvas pixels via toDataURL');
        
        // Poison canvas data by copying to a temp canvas and shifting 1 pixel slightly
        try {
          const tempCanvas = document.createElement('canvas');
          tempCanvas.width = this.width;
          tempCanvas.height = this.height;
          const tempCtx = tempCanvas.getContext('2d');
          if (tempCtx) {
            tempCtx.drawImage(this, 0, 0);
            const imgData = tempCtx.getImageData(0, 0, 1, 1);
            imgData.data[0] = (imgData.data[0] + 1) % 256; // Shift R channel by 1
            tempCtx.putImageData(imgData, 0, 0);
            return originalToDataURL.apply(tempCanvas, args);
          }
        } catch (err) {}
      }
      return originalToDataURL.apply(this, args);
    };

    const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;
    CanvasRenderingContext2D.prototype.getImageData = function(sx, sy, sw, sh, ...args) {
      const imgData = originalGetImageData.call(this, sx, sy, sw, sh, ...args);
      if (extensionSettings.heuristicsEnabled && !hasRecentInteraction()) {
        reportBehavioralAlert('Canvas Fingerprinting', 'Reading canvas pixel bytes via getImageData');
        
        // Poison first pixel's red channel slightly
        if (imgData.data && imgData.data.length > 0) {
          imgData.data[0] = (imgData.data[0] + 1) % 256;
        }
      }
      return imgData;
    };
  } catch (e) {
    console.warn('[Shield Heuristics] Canvas hooking failed:', e);
  }

  // Hook Audio Fingerprinting
  try {
    const originalStartRendering = window.OfflineAudioContext?.prototype?.startRendering;
    if (originalStartRendering) {
      window.OfflineAudioContext.prototype.startRendering = function(...args) {
        if (extensionSettings.heuristicsEnabled && !hasRecentInteraction()) {
          reportBehavioralAlert('Audio Fingerprinting', 'Offline audio rendering invoked');
        }
        return originalStartRendering.apply(this, args);
      };
    }

    const originalGetByteFrequencyData = window.AnalyserNode?.prototype?.getByteFrequencyData;
    if (originalGetByteFrequencyData) {
      window.AnalyserNode.prototype.getByteFrequencyData = function(array, ...args) {
        if (extensionSettings.heuristicsEnabled && !hasRecentInteraction()) {
          reportBehavioralAlert('Audio Fingerprinting', 'Reading frequency context data');
        }
        return originalGetByteFrequencyData.call(this, array, ...args);
      };
    }
  } catch (e) {
    console.warn('[Shield Heuristics] Audio hooking failed:', e);
  }

  // Hook WebAssembly Execution
  try {
    const originalWasmInstantiate = WebAssembly.instantiate;
    WebAssembly.instantiate = function(bufferSource, importObject, ...args) {
      if (extensionSettings.heuristicsEnabled) {
        reportBehavioralAlert('WASM Loading', 'Instantiating WebAssembly binary module (suspicious cryptojacking signature)');
      }
      return originalWasmInstantiate.call(this, bufferSource, importObject, ...args);
    };

    const originalWasmInstantiateStreaming = WebAssembly.instantiateStreaming;
    if (originalWasmInstantiateStreaming) {
      WebAssembly.instantiateStreaming = function(source, importObject, ...args) {
        if (extensionSettings.heuristicsEnabled) {
          reportBehavioralAlert('WASM Streaming', 'Instantiating streaming WebAssembly module (potential coin miner)');
        }
        return originalWasmInstantiateStreaming.call(this, source, importObject, ...args);
      };
    }
  } catch (e) {
    console.warn('[Shield Heuristics] WASM hooking failed:', e);
  }

  // ─── Regex Engine ────────────────────────────────────────────────────────────
  const PATTERNS = {
    privateKey: {
      regex: /\b([0-9a-fA-F]{64})\b/g,
      label: 'Crypto Private Key',
      severity: 'high', // Downgraded to prevent SHA-256 blocks
      desc: 'Raw 64-character hex private key detected in outgoing payload.',
    },
    ethereumAddress: {
      regex: /\b(0x[a-fA-F0-9]{40})\b/g,
      label: 'Ethereum/EVM Address',
      severity: 'high',
      desc: 'Ethereum or EVM-compatible wallet address found in payload.',
    },
    bitcoinAddress: {
      regex: /\b([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{11,71})\b/g,
      label: 'Bitcoin Address',
      severity: 'high',
      desc: 'Bitcoin wallet address detected in outgoing payload.',
    },
    seedPhrase: {
      regex: /\b(abandon|ability|able|about|above|absent|absorb|abstract|absurd|abuse|access|accident|account|accuse|achieve|acid|acoustic|acquire|across|act|action|actor|actress|actual|adapt|add|addict|address|adjust|admit|adult|advance|advice|aerobic|afford|afraid|again|age|agent|agree|ahead|aim|air|airport|aisle|alarm|album|alcohol|alert|alien|align|alive|alley|allow|almost|alone|alpha|already|alter|always|amateur|amazing|among|amount|amused|analyst|anchor|ancient|anger|angle|angry|animal|ankle|announce|annual|another|antenna|antique|anxiety|apart|apology|appear|apple|approve|april|arch|arctic|area|around|arrange|arrest|arrive|arrow|art|artefact|artist|artwork|ask|aspect|assault|asset|assist|assume|asthma|athlete|atom|attack|attend|attitude|attract|auction|audit|august|aunt|author|auto|autumn|average|avocado|avoid|awake|aware|away|awesome|awful|awkward|axis|baby|balance|bamboo|banana|banner|barely|bargain|barrel|base|basic|basket|battle|beach|bean|beauty|become|beef|before|begin|behave|behind|believe|below|belt|bench|benefit|best|betray|better|between|beyond|bicycle|bid|bike|bind|biology|bird|birth|bitter|black|blade|blame|blanket|blast|bleak|bless|blind|blood|blossom|blouse|blue|blur|blush|board|boat|body|boil|bomb|bone|bonus|book|boost|border|boring|borrow|boss|bottom|bounce|box|boy|bracket|brain|brand|brave|breeze|brick|bridge|brief|bright|bring|brisk|broccoli|broken|bronze|broom|brother|brown|brush|bubble|buddy|budget|buffalo|build|bulb|bulk|bullet|bundle|bunker|burden|burger|burst|bus|business|busy|butter|buyer|buzz|cabbage|cabin|cable|cactus|cage|cake|call|calm|camera|camp|can|canal|cancel|candy|cannon|canvas|canyon|capable|capital|captain|carbon|card|cargo|carpet|carry|cart|case|cash|casino|castle|casual|cat|catalog|catch|category|cattle|caught|cause|caution|cave|ceiling|celery|cement|census|century|cereal|certain|chair|chaos|chapter|charge|chase|chat|cheap|check|cheese|chef|cherry|chest|chicken|chief|child|chimney|choice|choose|chronic|chuckle|chunk|cigar|cinema|circle|citizen|city|civil|claim|clap|clarify|claw|clay|clean|clerk|clever|click|client|cliff|climb|clinic|clip|clock|clog|close|cloth|cloud|clown|club|clump|cluster|clutch|coach|coast|coconut|code|coffee|coil|coin|collect|color|column|combine|come|comfort|comic|common|company|concert|conduct|confirm|congress|connect|consider|control|convince|cook|cool|copper|copy|coral|core|corn|correct|cost|cotton|couch|country|couple|course|cousin|cover|coyote|crack|cradle|craft|cram|crane|crash|crazy|cream|credit|creek|crew|cricket|crime|crisp|critic|cross|crouch|crowd|crucial|cruel|cruise|crumble|crunch|crush|cry|crystal|cube|culture|cup|cupboard|curious|current|curtain|curve|cushion|custom|cute|cycle|dad|damage|damp|dance|danger|daring|dash|daughter|dawn|day|deal|debate|debris|decade|december|decide|decline|decorate|decrease|deer|defense|define|defy|degree|delay|deliver|demand|demise|denial|dentist|deny|depart|depend|deposit|depth|deputy|derive|describe|desert|design|desk|despair|destroy|detail|detect|develop|device|devote|diagram|dial|diamond|diary|dice|diesel|diet|differ|digital|dignity|dilemma|dinner|dinosaur|direct|dirt|disagree|discover|disease|dish|dismiss|disorder|display|distance|divert|divide|divorce|dizzy|doctor|document|dog|doll|dolphin|domain|donate|donkey|donor|door|dose|double|dove|draft|dragon|drama|drastic|draw|dream|dress|drift|drill|drink|drip|drive|drop|drum|dry|duck|dumb|dune|during|dust|dutch|duty|dwarf|dynamic|eager|eagle|early|earn|earth|easily|east|easy|echo|ecology|edge|edit|educate|effort|egg|eight|either|elbow|elder|electric|elegant|element|elephant|elevator|elite|else|embark|embody|embrace|emerge|emotion|employ|empower|empty|enable|enact|endless|endorse|enemy|energy|enforce|engage|engine|enhance|enjoy|enlist|enough|enrich|enroll|ensure|enter|entire|entry|envelope|episode|equal|equip|erase|erode|erosion|error|erupt|escape|essay|essence|estate|eternal|ethics|evidence|evil|evoke|evolve|exact|example|excess|exchange|excite|exclude|exercise|exhaust|expile|exotic|expand|expire|explain|expose|express|extend|extra|eye|fable|face|faculty|faint|faith|fall|false|fame|family|famous|fan|fancy|fantasy|far|fashion|fat|fatal|father|fatigue|fault|favorite|feature|february|federal|fee|feed|feel|feet|fellow|felt|fence|festival|fetch|fever|few|fiber|fiction|field|figure|file|film|filter|final|find|fine|finger|finish|fire|firm|first|fiscal|fish|fit|fitness|fix|flag|flame|flash|flat|flavor|flee|flight|flip|float|flock|floor|flower|fluid|flush|fly|foam|focus|fog|foil|follow|food|foot|force|forest|forget|fork|fortune|forum|forward|fossil|foster|found|fox|fragile|frame|frequent|fresh|friend|fringe|frog|front|frost|frown|frozen|fruit|fuel|fun|funny|furnace|fury|future|gadget|gain|galaxy|gallery|game|gap|garbage|garden|garlic|garment|gas|gasp|gate|gather|gauge|gaze|general|genius|genre|gentle|genuine|gesture|ghost|giant|gift|giggle|ginger|giraffe|girl|give|glad|glance|glare|glass|glide|glimpse|globe|gloom|glory|glove|glow|glue|goat|goddess|gold|good|goose|gorilla|gospel|gossip|govern|gown|grab|grace|grain|grant|grape|grasp|grass|gravity|great|green|grid|grief|grit|grocery|group|grow|grunt|guard|guide|guilt|guitar|gun|gym|habit|hair|half|hammer|hamster|hand|happy|harsh|harvest|hat|haunt|hawk|hazard|head|health|heart|heavy|hedgehog|height|hello|helmet|help|hen|hero|hidden|high|hill|hint|hip|hire|history|hobby|hockey|hold|hole|holiday|hollow|home|honey|hood|hope|horn|horror|horse|hospital|host|hour|hover|hub|huge|human|humble|humor|hundred|hungry|hunt|hurdle|hurry|hurt|husband|hybrid|ice|icon|ignore|ill|illegal|image|imitate|immense|immune|impact|impose|improve|impulse|inbox|income|index|indicate|indoor|industry|infant|inflict|inform|inhale|inject|inner|innocent|input|inquiry|insane|insect|inside|inspire|install|intact|interest|into|invest|invite|involve|iron|island|isolate|issue|item|ivory|jacket|jaguar|jar|jazz|jealous|jeans|jelly|jewel|job|join|joke|journey|joy|judge|juice|jump|jungle|junior|junk|just|kangaroo|keen|keep|ketchup|key|kick|kid|kingdom|kiss|kit|kitchen|kite|kitten|kiwi|knee|knife|knock|know|lab|lamp|language|laptop|large|later|laugh|laundry|lava|law|lawn|lawsuit|layer|lazy|leader|learn|leave|lecture|left|legal|legend|lemon|lend|length|lens|leopard|lesson|letter|level|liar|liberty|library|license|life|lift|like|limb|limit|link|lion|liquid|list|little|live|lizard|load|loan|lobster|local|lock|logic|lonely|long|loop|lottery|loud|lounge|love|loyal|lucky|luggage|lumber|lunar|lunch|luxury|mad|magic|magnet|maid|main|mammal|mango|mansion|manual|maple|marble|march|margin|marine|market|marriage|mask|master|match|material|math|matrix|matter|maximum|maze|meadow|mean|medal|media|melody|melt|member|memory|mention|menu|mercy|merge|merit|merry|mesh|message|metal|method|middle|midnight|milk|million|mimic|mind|minimum|minor|minute|miracle|miss|mitten|mixture|mobile|model|modify|mom|monitor|monkey|monster|month|moon|moral|more|morning|mosquito|mother|motion|motor|mountain|mouse|move|movie|much|muffin|mule|multiply|muscle|museum|mushroom|music|must|mutual|myself|mystery|naive|name|napkin|narrow|nasty|nature|near|neck|need|negative|neglect|neither|nephew|nerve|nest|network|news|next|nice|night|noble|noise|nominee|noodle|normal|north|notable|note|nothing|notice|novel|now|nuclear|nurse|nut|oak|obey|object|oblige|obscure|obtain|ocean|october|odor|off|offer|office|often|oil|okay|old|olive|olympic|omit|once|onion|open|opera|oppose|option|orange|orbit|orchard|order|ordinary|organ|orient|original|orphan|ostrich|other|outdoor|outside|oval|over|own|oyster|ozone|pact|paddle|page|pair|palace|palm|panda|panel|panic|panther|paper|parade|parent|park|parrot|party|pass|patch|path|patrol|pause|pave|payment|peace|peanut|peasant|pelican|pen|penalty|pencil|people|pepper|perfect|permit|person|pet|phone|photo|phrase|physical|piano|picnic|picture|piece|pig|pigeon|pill|pilot|pink|pioneer|pipe|pistol|pitch|pizza|place|planet|plastic|plate|play|please|pledge|pluck|plug|plunge|poem|poet|point|polar|pole|police|pond|pony|pool|popular|portion|position|possible|post|potato|pottery|poverty|powder|power|practice|praise|predict|prefer|prepare|present|pretty|prevent|price|pride|primary|print|priority|prison|private|prize|problem|process|produce|profit|program|project|promote|proof|property|prosper|protect|proud|provide|public|pudding|pull|pulp|pulse|pumpkin|punish|pupil|purchase|purity|purpose|push|put|puzzle|pyramid|quality|quantum|quarter|question|quick|quit|quiz|quote|rabbit|raccoon|race|rack|radar|radio|rage|rail|rain|raise|rally|ramp|ranch|random|range|rapid|rare|rate|rather|raven|reach|ready|real|reason|rebel|rebuild|recall|receive|recipe|record|recycle|reduce|reflect|reform|refuse|region|regret|regular|reject|relax|release|relief|rely|remain|remember|remind|remove|render|renew|rent|reopen|repair|repeat|replace|report|require|rescue|resemble|resist|resource|response|result|retire|retreat|return|reunion|reveal|review|reward|rhythm|ribbon|rice|rich|ride|ridge|rifle|right|rigid|ring|riot|ripple|risk|ritual|rival|river|road|roast|robot|robust|rocket|romance|roof|rookie|room|rose|rotate|rough|royal|rubber|rude|rug|rule|run|runway|rural|sad|saddle|sadness|safe|sail|salad|salmon|salon|salt|salute|same|sample|sand|satisfy|satoshi|sauce|sausage|save|say|scale|scan|scatter|scene|scheme|scholar|science|scissors|scorpion|scout|scrap|screen|script|scrub|sea|search|season|seat|second|secret|section|security|seek|segment|select|sell|seminar|senior|sense|sentence|series|service|session|settle|setup|seven|shadow|shaft|shallow|share|shed|shell|sheriff|shift|shine|ship|shiver|shock|shoe|shoot|shop|short|shoulder|shove|shrimp|shrug|shuffle|shy|sibling|siege|sight|sign|silent|silk|silly|silver|similar|simple|since|sing|siren|sister|situate|six|size|skate|sketch|ski|skill|skin|skirt|skull|slab|slam|sleep|slender|slice|slide|slight|slim|slogan|slot|slow|slush|small|smart|smile|smoke|smooth|snack|snake|snap|sniff|snow|soap|soccer|social|sock|solar|soldier|solid|solution|solve|someone|song|soon|sorry|soul|sound|soup|source|south|space|spare|spatial|spawn|speak|special|speed|sphere|spice|spider|spike|spin|spirit|split|spoil|sponsor|spoon|spray|spread|spring|spy|square|squeeze|squirrel|stable|stadium|staff|stage|stairs|stamp|stand|start|state|stay|steak|steel|stem|step|stereo|stick|still|sting|stock|stomach|stone|stop|store|storm|story|stove|strategy|street|strike|strong|struggle|student|stuff|stumble|style|subject|submit|subway|success|sudden|suffer|sugar|suggest|suit|summer|sun|sunny|sunset|super|supply|supreme|sure|surface|surge|surprise|sustain|swallow|swamp|swap|swear|sweet|swift|swim|swing|switch|sword|symbol|system|symptom|syrup|table|tackle|tag|tail|talent|tank|tape|target|task|tattoo|taxi|teach|team|tell|ten|tenant|tennis|tent|term|test|text|thank|that|theme|then|theory|there|they|thing|this|thought|three|thrive|throw|thumb|thunder|ticket|tilt|timber|time|tiny|tip|tired|title|toast|tobacco|today|together|toilet|token|tomato|tomorrow|tone|tongue|tonight|tool|tooth|top|topic|topple|torch|tornado|tortoise|toss|total|tourist|toward|tower|town|trade|traffic|tragic|train|transfer|trap|trash|travel|tray|treat|tree|trend|trial|trick|trigger|trim|trip|trophy|trouble|truck|truly|trumpet|trust|truth|try|tube|tuition|tumble|tuna|tunnel|turkey|turn|turtle|twelve|twenty|twice|twin|twist|two|type|typical|ugly|umbrella|unable|unaware|uncle|uncover|under|undo|unfair|unfold|unhappy|uniform|unique|universe|unknown|unlock|until|unusual|unveil|update|upgrade|uphold|upon|upper|upset|urban|useful|useless|usual|utility|vacant|vacuum|vague|valid|valley|valve|van|vanish|vapor|various|vast|vault|vehicle|velvet|vendor|venture|venue|verb|verify|version|very|veteran|viable|vibrant|vicious|victory|video|view|village|vintage|violin|virtual|virus|visa|visit|visual|vital|vivid|vocal|voice|void|volcano|volume|vote|voyage|wage|wagon|wait|walk|wall|walnut|want|warfare|warm|warrior|waste|water|wave|way|wealth|weapon|wear|weasel|weather|web|wedding|weekend|weird|welcome|well|west|wet|whale|wheat|wheel|when|where|whip|whisper|wide|width|wife|wild|will|win|window|wine|wing|wink|winner|winter|wire|wisdom|wise|wish|witness|wolf|woman|wonder|wood|wool|word|world|worry|worth|wrap|wreck|wrestle|wrist|write|wrong|yard|year|yellow|you|young|youth|zebra|zero|zone|zoo)\b/gi,
      label: 'BIP39 Seed Phrase',
      severity: 'critical',
      desc: 'Potential crypto wallet seed phrase detected. This is your master key!',
      minMatches: 3,
    },
    creditCard: {
      regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b/g,
      label: 'Credit Card Number',
      severity: 'critical',
      desc: 'Credit card number found in outgoing network request payload.',
    },
    ssn: {
      regex: /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g,
      label: 'Social Security Number',
      severity: 'critical',
      desc: 'Potential SSN (US) detected in outgoing payload.',
    },
    apiKey: {
      regex: /\b(sk-[a-zA-Z0-9]{32,}|ghp_[a-zA-Z0-9]{36}|AIza[0-9A-Za-z\-_]{35}|AKIA[0-9A-Z]{16}|[a-zA-Z0-9+/]{40}={0,2})\b/g,
      label: 'API Key / Token',
      severity: 'high',
      desc: 'Possible API key or bearer token detected in outgoing payload.',
    },
  };

  /**
   * Run all pattern checks against a string payload.
   * Returns array of findings.
   */
  function inspectPayload(payload) {
    if (typeof payload !== 'string' || payload.length < 8) return [];

    // Limit scan size to prevent CPU lockups on large JSON/file uploads
    if (payload.length > 60000) {
      payload = payload.substring(0, 60000);
    }

    const findings = [];

    for (const [key, config] of Object.entries(PATTERNS)) {
      const matches = [...payload.matchAll(config.regex)];

      if (key === 'seedPhrase') {
        if (matches.length >= (config.minMatches || 3)) {
          findings.push({
            type: key,
            label: config.label,
            severity: config.severity,
            desc: config.desc,
            count: matches.length,
            sample: '***REDACTED***',
          });
        }
      } else if (matches.length > 0) {
        findings.push({
          type: key,
          label: config.label,
          severity: config.severity,
          desc: config.desc,
          count: matches.length,
          sample: '***REDACTED***',
        });
      }
    }

    return findings;
  }

  /**
   * Try decoding common obfuscation payloads.
   */
  function tryDecode(payload) {
    if (!payload || typeof payload !== 'string') return '';
    let decoded = payload;

    // 1. Try URL Decoding
    try {
      if (decoded.includes('%')) {
        decoded = decodeURIComponent(decoded);
      }
    } catch (e) {}

    // 2. Try Base64 Decoding
    try {
      const cleaned = decoded.trim();
      if (/^[A-Za-z0-9+/=]+$/.test(cleaned) && cleaned.length >= 8) {
        const b64Decoded = atob(cleaned);
        if (/^[\x20-\x7E\r\n\t]*$/.test(b64Decoded)) {
          decoded = b64Decoded;
        }
      }
    } catch (e) {}

    // 3. Try Hex Decoding
    try {
      const cleaned = decoded.trim();
      if (/^[0-9a-fA-F]+$/.test(cleaned) && cleaned.length % 2 === 0 && cleaned.length >= 16) {
        let hexDecoded = '';
        for (let i = 0; i < cleaned.length; i += 2) {
          hexDecoded += String.fromCharCode(parseInt(cleaned.substring(i, i + 2), 16));
        }
        if (/^[\x20-\x7E\r\n\t]*$/.test(hexDecoded)) {
          decoded = hexDecoded;
        }
      }
    } catch (e) {}

    return decoded;
  }


  /**
   * Redact sensitive credentials from the outgoing payload instead of blocking it outright.
   * This ensures the page functions normally but exfiltrated data is neutralized.
   */
  function sanitizePayload(payload) {
    if (!payload || typeof payload !== 'string') return payload;
    let sanitized = payload;
    for (const [key, config] of Object.entries(PATTERNS)) {
      if (config.severity === 'critical' || config.severity === 'high') {
        sanitized = sanitized.replaceAll(config.regex, '[REDACTED_BY_SHIELD]');
      }
    }
    return sanitized;
  }

  /**
   * Report findings to the content script bridge.
   */
  function reportFindings(url, method, findings, blocked) {
    window.dispatchEvent(
      new CustomEvent('__secext_payload_alert', {
        detail: { url, method, findings, blocked, timestamp: Date.now() },
      })
    );
  }

  // ─── Fetch Monkey-Patch ───────────────────────────────────────────────────────
  const _originalFetch = window.fetch;

  window.fetch = async function (...args) {
    try {
      const [input, init] = args;
      const url = typeof input === 'string' ? input : input?.url || '';
      const method = init?.method || 'GET';
      let bodyText = '';
      let isRequestObject = false;

      if (init?.body) {
        if (typeof init.body === 'string') {
          bodyText = init.body;
        } else if (init.body instanceof URLSearchParams) {
          bodyText = init.body.toString();
        } else if (init.body instanceof FormData) {
          for (const [k, v] of init.body.entries()) {
            bodyText += `${k}=${v}&`;
          }
        }
      } else if (input && typeof input === 'object' && typeof input.clone === 'function') {
        try {
          const clonedReq = input.clone();
          bodyText = await clonedReq.text();
          isRequestObject = true;
        } catch (e) {}
      }

      const applySanitization = (sanitizedBody) => {
        if (init && init.body) {
          if (typeof init.body === 'string') {
            init.body = sanitizedBody;
          } else if (init.body instanceof URLSearchParams) {
            init.body = new URLSearchParams(sanitizedBody);
          } else if (init.body instanceof FormData) {
            const newFd = new FormData();
            for (const pair of new URLSearchParams(sanitizedBody).entries()) {
              newFd.append(pair[0], pair[1]);
            }
            init.body = newFd;
          }
        } else if (isRequestObject && input) {
          const headers = new Headers(input.headers);
          const reqInit = {
            method: input.method,
            headers: headers,
            body: sanitizedBody,
            referrer: input.referrer,
            referrerPolicy: input.referrerPolicy,
            mode: input.mode,
            credentials: input.credentials,
            cache: input.cache,
            redirect: input.redirect,
            integrity: input.integrity,
            keepalive: input.keepalive,
            signal: input.signal
          };
          args[0] = new Request(input.url, reqInit);
        }
      };

      // 1. Static check first
      const findings = inspectPayload(bodyText);
      if (findings.length > 0) {
        const shouldSanitize = window.__secext_firewall === true && 
          findings.some(f => f.severity === 'critical');

        if (shouldSanitize) {
          console.warn('[Security Extension] SANITIZED critical data leak from fetch:', url);
          const sanitizedBody = sanitizePayload(bodyText);
          applySanitization(sanitizedBody);
          reportFindings(url, method, findings, true);
          return _originalFetch.apply(this, args);
        } else {
          reportFindings(url, method, findings, false);
        }
      }

      // 2. Decode check
      if (window.__secext_firewall === true) {
        const decodedBody = tryDecode(bodyText);
        
        // Check static rules on decoded content
        const decodedFindings = inspectPayload(decodedBody);
        if (decodedFindings.some(f => f.severity === 'critical')) {
          console.warn('[Security Extension] SANITIZED critical decoded leak from fetch:', url);
          const sanitizedBody = sanitizePayload(bodyText);
          applySanitization(sanitizedBody);
          reportFindings(url, method, decodedFindings, true);
          return _originalFetch.apply(this, args);
        }
      }
    } catch (e) {
      // Never break page functionality
    }

    return _originalFetch.apply(this, args);
  };

  // ─── XHR Monkey-Patch ────────────────────────────────────────────────────────
  const _originalOpen = XMLHttpRequest.prototype.open;
  const _originalSend = XMLHttpRequest.prototype.send;

  XMLHttpRequest.prototype.open = function (method, url, async, ...rest) {
    this.__secext_url = url;
    this.__secext_method = method;
    this.__secext_async = async !== false;
    return _originalOpen.call(this, method, url, async, ...rest);
  };

  XMLHttpRequest.prototype.send = function (body) {
    const xhr = this;
    const url = xhr.__secext_url || '';
    const method = xhr.__secext_method || 'POST';

    const getSanitizedBody = (rawBody) => {
      let bodyText = '';
      if (typeof rawBody === 'string') bodyText = rawBody;
      else if (rawBody instanceof URLSearchParams) bodyText = rawBody.toString();
      
      const sanitizedBodyText = sanitizePayload(bodyText);
      
      if (typeof rawBody === 'string') return sanitizedBodyText;
      if (rawBody instanceof URLSearchParams) return new URLSearchParams(sanitizedBodyText);
      return rawBody;
    };

    // If synchronous XHR, we cannot run async AI sandbox check, fallback to static check only
    if (xhr.__secext_async === false) {
      try {
        let bodyText = '';
        if (typeof body === 'string') bodyText = body;
        else if (body instanceof URLSearchParams) bodyText = body.toString();

        const findings = inspectPayload(bodyText);
        if (findings.length > 0) {
          const shouldSanitize = window.__secext_firewall === true &&
            findings.some(f => f.severity === 'critical');

          if (shouldSanitize) {
            console.warn('[Security Extension] SANITIZED critical data leak from Sync XHR:', url);
            const finalBody = getSanitizedBody(body);
            reportFindings(url, method, findings, true);
            return _originalSend.call(xhr, finalBody);
          } else {
            reportFindings(url, method, findings, false);
          }
        }
      } catch (e) {}

      return _originalSend.call(xhr, body);
    }

    // Async XHR interception wrapper
    (async () => {
      try {
        let bodyText = '';
        if (typeof body === 'string') bodyText = body;
        else if (body instanceof URLSearchParams) bodyText = body.toString();

        // 1. Static check first
        const findings = inspectPayload(bodyText);
        if (findings.length > 0) {
          const shouldSanitize = window.__secext_firewall === true &&
            findings.some(f => f.severity === 'critical');

          if (shouldSanitize) {
            console.warn('[Security Extension] SANITIZED critical data leak from XHR:', url);
            const finalBody = getSanitizedBody(body);
            reportFindings(url, method, findings, true);
            _originalSend.call(xhr, finalBody);
            return;
          }
        }

      // 2. Decode check
      if (window.__secext_firewall === true) {
        const decodedBody = tryDecode(bodyText);
        
        // Check static rules on decoded content
        const decodedFindings = inspectPayload(decodedBody);
        if (decodedFindings.some(f => f.severity === 'critical')) {
          console.warn('[Security Extension] SANITIZED critical decoded leak from XHR:', url);
          const finalBody = getSanitizedBody(body);
          reportFindings(url, method, decodedFindings, true);
          _originalSend.call(xhr, finalBody);
          return;
        }
      }
    } catch (e) {}

    // Execute original XHR send
    try {
      _originalSend.call(xhr, body);
    } catch (e) {}
  })();
};

console.log('[Security Extension] Payload inspector active');
})();
