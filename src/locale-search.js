// Identifier identity never uses prose aliases or punctuation/diacritic folding.
export const normalizeSearchIdentifier = value => String(value??'').normalize('NFC').toLowerCase().trim().replace(/\s+/gu,' ');
export const normalizeSearchProse = value => String(value??'').normalize('NFC').toLowerCase().replace(/[^\p{L}\p{N}\p{M}+]+/gu,' ').trim().replace(/\s+/gu,' ');
const searchValues = value => Array.isArray(value)?value:value==null?[]:[value];
const searchUnique = values => [...new Set(values.filter(Boolean))];
const searchTokens = values => new Set(values.flatMap(value=>value.split(' ')));

// These are search-copy policies, not transliteration or display rewriting.
// Latin accents fold after NFD; Cyrillic й/і/ї/є/ґ remain distinct. Hebrew
// niqqud/cantillation folds except shin/sin dots and rafe. Arabic vowel and
// recitation marks fold, but hamza/maddah and letter variants remain distinct.
const foldSearchProse = value => value.normalize('NFD')
  .replace(/\p{Script=Latin}\p{M}*/gu,cluster=>cluster.replace(/\p{M}/gu,''))
  .replace(/[ßł]/gu,char=>char==='ß'?'ss':'l')
  .replace(/[\u0591-\u05BD\u05C4\u05C5\u05C7\u0610-\u061A\u064B-\u0652\u0656-\u065F\u0670\u06D6-\u06DC\u06DF-\u06E4\u06E7\u06E8\u06EA-\u06ED]/gu,'')
  .normalize('NFC');
const normalizedSearchAliases = original => {
  if(!/[^\x00-\x7f]/.test(original))return [];
  const folded=normalizeSearchProse(foldSearchProse(original));
  const expanded=/[äöü]/u.test(original)?normalizeSearchProse(foldSearchProse(original.replace(/[äöü]/gu,char=>({ä:'ae',ö:'oe',ü:'ue'}[char])))):folded;
  return searchUnique([folded,expanded]).filter(alias=>alias!==original);
};
export const searchAliases = value => normalizedSearchAliases(normalizeSearchProse(value));

export function prepareSearchQuery(raw,{aliases=true}={}) {
  const value=String(raw??''),phrase=normalizeSearchProse(value);
  const searchable=/[\p{L}\p{N}]/u.test(phrase);
  const phrases=searchable?searchUnique([phrase,...(aliases?normalizedSearchAliases(phrase):[])]):[];
  return {raw:value,empty:!value.trim(),identifier:normalizeSearchIdentifier(value),phrase,terms:searchTokens(phrase?[phrase]:[]),variants:phrases.map(text=>({phrase:text,terms:[...searchTokens([text])]}))};
}

/** Small presentation metadata only; callers retain their canonical records. */
export function createSearchFields({phrases=[],identifiers=[],context=[],aliases=true}={}) {
  const proseKeys=values=>searchUnique(values.flatMap(value=>{const normalized=normalizeSearchProse(value);return [normalized,...(aliases?normalizedSearchAliases(normalized):[])];}));
  const exact=new Set(searchValues(identifiers).map(normalizeSearchIdentifier).filter(Boolean));
  // A name repeated in phrases is still an identifier, not an independent
  // punctuation-folded exact prose match. Keep its forgiving tokens below.
  const strong=proseKeys(searchValues(phrases).filter(value=>!exact.has(normalizeSearchIdentifier(value))));
  const identifierPhrases=searchUnique(searchValues(identifiers).map(normalizeSearchProse));
  return {
    exact,strong:new Set(strong),tokens:searchTokens(strong),
    identifierTokens:searchTokens(identifierPhrases),
    contextTokens:searchTokens(proseKeys(searchValues(context))),
  };
}
export function mergeSearchFields(...sources) {
  const result={};
  for(const key of ['exact','strong','tokens','identifierTokens','contextTokens']){
    const values=new Set();
    for(const source of sources)if(source)for(const value of source[key])values.add(value);
    result[key]=values;
  }
  return result;
}
const searchHasPrefix = (tokens,term) => {
  if(!/^.{3}/u.test(term))return false;
  // A prefix cannot erase the mechanism's immediately following '+'.
  for(const token of tokens)if(token.startsWith(term)&&token[term.length]!=='+')return true;
  return false;
};
const searchIn = (fields,parent,key,term,prefix=false) => fields[key].has(term)||parent?.[key].has(term)||(prefix&&(searchHasPrefix(fields[key],term)||(parent&&searchHasPrefix(parent[key],term))));

/** Original SEARCH01 tiers: exact phrase 0, tokens 1, prefix 2, context 3. */
export function rankSearchFields(fields,query,parent=null) {
  if(query.empty)return 0;
  if(!query.variants.length)return null;
  if(searchIn(fields,parent,'exact',query.identifier))return 0;
  let best=null;
  for(const variant of query.variants){
    if(searchIn(fields,parent,'strong',variant.phrase))return 0;
    let rank=1;
    for(const term of variant.terms){
      // Aliased query tokens cannot weaken a protected identifier. Unchanged
      // tokens may still combine identifiers with translated/forgiving prose.
      const identifier=query.terms.has(term);
      if(searchIn(fields,parent,'tokens',term)||(identifier&&searchIn(fields,parent,'identifierTokens',term)))continue;
      if(searchIn(fields,parent,'tokens',term,true)||(identifier&&searchIn(fields,parent,'identifierTokens',term,true))){rank=Math.max(rank,2);continue;}
      if(searchIn(fields,parent,'contextTokens',term,true)){rank=3;continue;}
      rank=null;break;
    }
    if(rank!==null&&(best===null||rank<best))best=rank;
  }
  return best;
}

const activeSearchCaches = new WeakMap();
const searchMetadataSignature = record => JSON.stringify([record.id,record.title,record.category,record.summary,record.selectedLabel,record.searchText,record.searchTags,record.searchIdentifiers,record.searchContext,record.searchVariants,record.name,record.meaning,record.origin,record.purpose]);
/** Only the active locale/revision survives in this cache; no models are run. */
export function localizedSearchIndex(localization,kind,id,canonicalRecord,context={}) {
  if(!localization?.searchEntry)return null;
  const identity=localization.searchCache instanceof Map?localization.searchCache:localization;
  if(localization.locale==='en'){activeSearchCaches.delete(identity);return null;}
  let cache=activeSearchCaches.get(identity);
  if(!cache||cache.locale!==localization.locale||cache.revision!==localization.revision){
    cache={locale:localization.locale,revision:localization.revision,records:new WeakMap()};activeSearchCaches.set(identity,cache);
  }
  let entries=cache.records.get(canonicalRecord);
  if(!entries){entries=new Map();cache.records.set(canonicalRecord,entries);}
  const key=JSON.stringify([kind,id]),signature=JSON.stringify(context)+'\0'+searchMetadataSignature(canonicalRecord),cached=entries.get(key);
  if(cached?.signature===signature)return cached;
  const entry=localization.searchEntry(kind,id,canonicalRecord,context)||{};
  const result={signature,entry,base:createSearchFields({phrases:[entry.title,...searchValues(entry.searchTags)],context:[entry.category,entry.summary,entry.meaning,entry.origin,entry.purpose,entry.searchText,...searchValues(entry.searchContext)]}),variants:searchValues(entry.searchVariants).map(variant=>({id:variant.id,fields:createSearchFields({phrases:[variant.label,...searchValues(variant.searchTags)],context:searchValues(variant.searchContext)})}))};
  entries.set(key,result);
  return result;
}
