'use strict';

/**
 * @ngdoc filter
 * @name linky
 * @kind function
 *
 * @description
 * Finds links in text input and turns them into html links. Supports `http/https/ftp/sftp/mailto` and
 * plain email address links.
 *
 * Requires the {@link ngSanitize `ngSanitize`} module to be installed.
 *
 * @param {string} text Input text.
 * @param {string} [target] Window (`_blank|_self|_parent|_top`) or named frame to open links in.
 * @param {object|function(url)} [attributes] Add custom attributes to the link element.
 *
 *    Can be one of:
 *
 *    - `object`: A map of attributes
 *    - `function`: Takes the url as a parameter and returns a map of attributes
 *
 *    If the map of attributes contains a value for `target`, it overrides the value of
 *    the target parameter.
 *
 *
 * @returns {string} Html-linkified and {@link $sanitize sanitized} text.
 *
 * @usage
   <span ng-bind-html="linky_expression | linky"></span>
 *
 * @example
   <example module="linkyExample" deps="angular-sanitize.js" name="linky-filter">
     <file name="index.html">
       <div ng-controller="ExampleController">
       Snippet: <textarea ng-model="snippet" cols="60" rows="3"></textarea>
       <table>
         <tr>
           <th>Filter</th>
           <th>Source</th>
           <th>Rendered</th>
         </tr>
         <tr id="linky-filter">
           <td>linky filter</td>
           <td>
             <pre>&lt;div ng-bind-html="snippet | linky"&gt;<br>&lt;/div&gt;</pre>
           </td>
           <td>
             <div ng-bind-html="snippet | linky"></div>
           </td>
         </tr>
         <tr id="linky-target">
          <td>linky target</td>
          <td>
            <pre>&lt;div ng-bind-html="snippetWithSingleURL | linky:'_blank'"&gt;<br>&lt;/div&gt;</pre>
          </td>
          <td>
            <div ng-bind-html="snippetWithSingleURL | linky:'_blank'"></div>
          </td>
         </tr>
         <tr id="linky-custom-attributes">
          <td>linky custom attributes</td>
          <td>
            <pre>&lt;div ng-bind-html="snippetWithSingleURL | linky:'_self':{rel: 'nofollow'}"&gt;<br>&lt;/div&gt;</pre>
          </td>
          <td>
            <div ng-bind-html="snippetWithSingleURL | linky:'_self':{rel: 'nofollow'}"></div>
          </td>
         </tr>
         <tr id="escaped-html">
           <td>no filter</td>
           <td><pre>&lt;div ng-bind="snippet"&gt;<br>&lt;/div&gt;</pre></td>
           <td><div ng-bind="snippet"></div></td>
         </tr>
       </table>
     </file>
     <file name="script.js">
       angular.module('linkyExample', ['ngSanitize'])
         .controller('ExampleController', ['$scope', function($scope) {
           $scope.snippet =
             'Pretty text with some links:\n' +
             'http://angularjs.org/,\n' +
             'mailto:us@somewhere.org,\n' +
             'another@somewhere.org,\n' +
             'and one more: ftp://127.0.0.1/.';
           $scope.snippetWithSingleURL = 'http://angularjs.org/';
         }]);
     </file>
     <file name="protractor.js" type="protractor">
       it('should linkify the snippet with urls', function() {
         expect(element(by.id('linky-filter')).element(by.binding('snippet | linky')).getText()).
             toBe('Pretty text with some links: http://angularjs.org/, us@somewhere.org, ' +
                  'another@somewhere.org, and one more: ftp://127.0.0.1/.');
         expect(element.all(by.css('#linky-filter a')).count()).toEqual(4);
       });

       it('should not linkify snippet without the linky filter', function() {
         expect(element(by.id('escaped-html')).element(by.binding('snippet')).getText()).
             toBe('Pretty text with some links: http://angularjs.org/, mailto:us@somewhere.org, ' +
                  'another@somewhere.org, and one more: ftp://127.0.0.1/.');
         expect(element.all(by.css('#escaped-html a')).count()).toEqual(0);
       });

       it('should update', function() {
         element(by.model('snippet')).clear();
         element(by.model('snippet')).sendKeys('new http://link.');
         expect(element(by.id('linky-filter')).element(by.binding('snippet | linky')).getText()).
             toBe('new http://link.');
         expect(element.all(by.css('#linky-filter a')).count()).toEqual(1);
         expect(element(by.id('escaped-html')).element(by.binding('snippet')).getText())
             .toBe('new http://link.');
       });

       it('should work with the target property', function() {
        expect(element(by.id('linky-target')).
            element(by.binding("snippetWithSingleURL | linky:'_blank'")).getText()).
            toBe('http://angularjs.org/');
        expect(element(by.css('#linky-target a')).getAttribute('target')).toEqual('_blank');
       });

       it('should optionally add custom attributes', function() {
        expect(element(by.id('linky-custom-attributes')).
            element(by.binding("snippetWithSingleURL | linky:'_self':{rel: 'nofollow'}")).getText()).
            toBe('http://angularjs.org/');
        expect(element(by.css('#linky-custom-attributes a')).getAttribute('rel')).toEqual('nofollow');
       });
     </file>
   </example>
 */
angular.module('ngSanitize').filter('linky', ['$sanitize', function($sanitize) {
  // Finds the same links as the old single regex
  //   /((s?ftp|https?):\/\/|(www\.)|(mailto:)?[A-Za-z0-9._%+-]+@)\S*[^\s.;,(){}<>"\u201d\u2019]/i
  // but in linear time. The email part of that regex was retried at every position of a long run
  // of letters, which took quadratic time (CVE-2025-4690).
  var LINKY_URL_REGEXP = /((s?ftp|https?):\/\/|(www\.))\S*[^\s.;,(){}<>"\u201d\u2019]/ig,
      LINKY_EMAIL_CHAR_REGEXP = /^[A-Za-z0-9._%+-]$/,
      LINKY_LAST_CHAR_REGEXP = /^[^\s.;,(){}<>"\u201d\u2019]$/,
      WHITESPACE_REGEXP = /^\s$/,
      MAILTO_PREFIX_REGEXP = /^mailto:$/i;

  // Returns a function that, given a start position, returns the next link at or after it as
  // `{index, text, scheme, www, mailto}`, or null. Positions must not go backwards.
  function linkFinder(text) {
    var urlMatch = null, urlSearchedFrom = -1;
    var email = null, atSearchFrom = 0;

    function nextUrl(pos) {
      if (urlSearchedFrom === -1 || (urlMatch && urlMatch.index < pos) || (!urlMatch && urlSearchedFrom > pos)) {
        LINKY_URL_REGEXP.lastIndex = pos;
        urlMatch = LINKY_URL_REGEXP.exec(text);
        urlSearchedFrom = pos;
      }
      return urlMatch;
    }

    // Finds the end of `\S*[^\s.;,(){}<>"\u201d\u2019]` starting at `from`, or -1.
    function tailEnd(from) {
      var end = from;
      while (end < text.length && !WHITESPACE_REGEXP.test(text.charAt(end))) end++;
      while (end > from && !LINKY_LAST_CHAR_REGEXP.test(text.charAt(end - 1))) end--;
      return end > from ? end : -1;
    }

    function nextEmail(pos) {
      while (true) {
        if (email && email.runStart >= 0) {
          var start = Math.max(email.runStart, pos);
          if (start < email.at) {
            var mailto = start >= pos + 7 && MAILTO_PREFIX_REGEXP.test(text.slice(start - 7, start));
            if (mailto) start -= 7;
            return {index: start, end: email.end, mailto: mailto};
          }
        }
        // Find the next usable `@`.
        var at = text.indexOf('@', Math.max(atSearchFrom, pos));
        if (at === -1) {
          email = null;
          atSearchFrom = text.length;
          return null;
        }
        atSearchFrom = at + 1;
        var runStart = at;
        while (runStart > 0 && LINKY_EMAIL_CHAR_REGEXP.test(text.charAt(runStart - 1))) runStart--;
        var end = runStart < at ? tailEnd(at + 1) : -1;
        email = {at: at, runStart: end === -1 ? -1 : runStart, end: end};
      }
    }

    return function(pos) {
      var url = nextUrl(pos);
      var mail = nextEmail(pos);
      if (url && (!mail || url.index <= mail.index)) {
        return {index: url.index, text: url[0], scheme: url[2], www: url[3]};
      }
      if (mail) {
        return {index: mail.index, text: text.slice(mail.index, mail.end), mailto: mail.mailto};
      }
      return null;
    };
  }

  var MAILTO_REGEXP = /^mailto:/i;

  var linkyMinErr = angular.$$minErr('linky');
  var isDefined = angular.isDefined;
  var isFunction = angular.isFunction;
  var isObject = angular.isObject;
  var isString = angular.isString;

  return function(text, target, attributes) {
    if (text == null || text === '') return text;
    if (!isString(text)) throw linkyMinErr('notstring', 'Expected string but received: {0}', text);

    var attributesFn =
      isFunction(attributes) ? attributes :
      isObject(attributes) ? function getAttributesObject() {return attributes;} :
      function getEmptyAttributesObject() {return {};};

    var link;
    var findLink = linkFinder(text);
    var pos = 0;
    var html = [];
    var url;
    while ((link = findLink(pos))) {
      // We can not end in these as they are sometimes found at the end of the sentence
      url = link.text;
      // if we did not match ftp/http/www/mailto then assume mailto
      if (!link.scheme && !link.mailto) {
        url = (link.www ? 'http://' : 'mailto:') + url;
      }
      addText(text.substring(pos, link.index));
      addLink(url, link.text.replace(MAILTO_REGEXP, ''));
      pos = link.index + link.text.length;
    }
    addText(text.substring(pos));
    return $sanitize(html.join(''));

    function addText(text) {
      if (!text) {
        return;
      }
      html.push(sanitizeText(text));
    }

    function addLink(url, text) {
      var key, linkAttributes = attributesFn(url);
      html.push('<a ');

      for (key in linkAttributes) {
        html.push(key + '="' + linkAttributes[key] + '" ');
      }

      if (isDefined(target) && !('target' in linkAttributes)) {
        html.push('target="',
                  target,
                  '" ');
      }
      html.push('href="',
                url.replace(/"/g, '&quot;'),
                '">');
      addText(text);
      html.push('</a>');
    }
  };
}]);
