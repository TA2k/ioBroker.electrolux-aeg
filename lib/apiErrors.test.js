'use strict';

const { expect } = require('chai');
const { classifyLoginAnswer } = require('./apiErrors');

describe('classifyLoginAnswer', () => {
  const session = { sessionInfo: { sessionToken: 't', sessionSecret: 's' } };

  it('accepts an answer with session token and secret', () => {
    expect(classifyLoginAnswer(session)).to.equal('ok');
  });

  it('treats a session without its secret as unusable', () => {
    expect(classifyLoginAnswer({ sessionInfo: { sessionToken: 't' } })).to.equal('failed');
  });

  for (const errorCode of [403042, 401030, 401020, '403042']) {
    it('reports error code ' + JSON.stringify(errorCode) + ' as rejected credentials in a 200 body', () => {
      expect(classifyLoginAnswer({ errorCode, errorMessage: 'x' })).to.equal('rejected');
    });
  }

  it('reports rejected credentials that arrive as a 403', () => {
    const error = Object.assign(new Error('403'), { response: { status: 403, data: { errorCode: 403042 } } });
    expect(classifyLoginAnswer(undefined, error)).to.equal('rejected');
  });

  it('keeps other account errors apart from wrong credentials', () => {
    expect(classifyLoginAnswer({ errorCode: 206002 })).to.equal('failed');
    const error = Object.assign(new Error('400'), { response: { status: 400, data: {} } });
    expect(classifyLoginAnswer(undefined, error)).to.equal('failed');
  });

  it('reports a missing answer or a server error as unreachable', () => {
    expect(classifyLoginAnswer(undefined, Object.assign(new Error('timeout'), { code: 'ECONNABORTED' }))).to.equal('unreachable');
    const error = Object.assign(new Error('503'), { response: { status: 503, data: { errorCode: 403042 } } });
    expect(classifyLoginAnswer(undefined, error)).to.equal('unreachable');
  });

  it('copes with empty and malformed bodies', () => {
    for (const data of [undefined, null, '', 'html', [], {}]) {
      expect(classifyLoginAnswer(data)).to.equal('failed');
    }
  });
});
