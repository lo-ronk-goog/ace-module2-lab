/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { AllHtmlEntities as Entities } from 'html-entities'
import config from 'config'
import fs from 'node:fs/promises'

import * as challengeUtils from '../lib/challengeUtils'
import { themes } from '../views/themes/themes'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'

const entities = new Entities()

function safeEvaluate (code: string): string {
  let remaining = code.trim()
  let result = ''
  let lastTokenWasValue = false

  while (remaining.length > 0) {
    const wsMatch = remaining.match(/^\s+/)
    if (wsMatch) {
      remaining = remaining.substring(wsMatch[0].length)
      continue
    }

    const strMatch = remaining.match(/^'([^'\\]*(?:\\.[^'\\]*)*)'/) ||
                     remaining.match(/^"([^"\\]*(?:\\.[^"\\]*)*)"/) ||
                     remaining.match(/^`([^`\\]*(?:\\.[^`\\]*)*)`/)
    if (strMatch) {
      if (lastTokenWasValue) {
        throw new Error('Unexpected string literal')
      }
      const content = strMatch[1]
      const unescaped = content.replace(/\\(.)/g, '$1')
      result += unescaped
      lastTokenWasValue = true
      remaining = remaining.substring(strMatch[0].length)
      continue
    }

    const numMatch = remaining.match(/^\d+(\.\d+)?/)
    if (numMatch) {
      if (lastTokenWasValue) {
        throw new Error('Unexpected number literal')
      }
      result += numMatch[0]
      lastTokenWasValue = true
      remaining = remaining.substring(numMatch[0].length)
      continue
    }

    const boolMatch = remaining.match(/^(true|false)\b/)
    if (boolMatch) {
      if (lastTokenWasValue) {
        throw new Error('Unexpected boolean literal')
      }
      result += boolMatch[0]
      lastTokenWasValue = true
      remaining = remaining.substring(boolMatch[0].length)
      continue
    }

    const opMatch = remaining.match(/^\+/)
    if (opMatch) {
      if (!lastTokenWasValue) {
        throw new Error('Unexpected operator +')
      }
      lastTokenWasValue = false
      remaining = remaining.substring(opMatch[0].length)
      continue
    }

    throw new Error('Unsafe token or syntax error')
  }

  if (!lastTokenWasValue && code.trim().length > 0) {
    throw new Error('Trailing operator')
  }

  return result
}

function favicon () {
  return utils.extractFilename(config.get('application.favicon'))
}

export function getUserProfile () {
  return async (req: Request, res: Response, next: NextFunction) => {
    let template: string
    try {
      template = await fs.readFile('views/userProfile.pug', { encoding: 'utf-8' })
    } catch (err) {
      next(err)
      return
    }

    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress)); return
    }

    let user: UserModel | null
    try {
      user = await UserModel.findByPk(loggedInUser.data.id)
    } catch (error) {
      next(error)
      return
    }

    if (!user) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }

    let username = user.username

    if (username?.match(/#{(.*)}/) !== null && utils.isChallengeEnabled(challenges.usernameXssChallenge)) {
      req.app.locals.abused_ssti_bug = true
      const code = username?.substring(2, username.length - 1)
      try {
        if (!code) {
          throw new Error('Username is null')
        }
        username = safeEvaluate(code)
      } catch (err) {
        username = '\\\\' + username
      }
    } else {
      username = '\\\\' + username
    }

    const themeKey = config.get<string>('application.theme') as keyof typeof themes
    const theme = themes[themeKey] || themes['bluegrey-lightgreen']

    if (username) {
      template = template.replace(/_username_/g, username)
    }
    template = template.replace(/_emailHash_/g, security.hash(user?.email))
    template = template.replace(/_title_/g, entities.encode(config.get<string>('application.name')))
    template = template.replace(/_favicon_/g, favicon())
    template = template.replace(/_bgColor_/g, theme.bgColor)
    template = template.replace(/_textColor_/g, theme.textColor)
    template = template.replace(/_navColor_/g, theme.navColor)
    template = template.replace(/_primLight_/g, theme.primLight)
    template = template.replace(/_primDark_/g, theme.primDark)
    template = template.replace(/_logo_/g, utils.extractFilename(config.get('application.logo')))

    try {
      const pug = (await import('pug')).default
      const fn = pug.compile(template)
      const CSP = `img-src 'self' ${user?.profileImage}; script-src 'self' 'unsafe-eval'`

      challengeUtils.solveIf(challenges.usernameXssChallenge, () => {
        return username && user?.profileImage.match(/;[ ]*script-src(.)*'unsafe-inline'/g) !== null && utils.contains(username, '<script>alert(`xss`)</script>')
      })

      res.set({
        'Content-Security-Policy': CSP
      })

      res.send(fn(user))
    } catch (err) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
    }
  }
}
