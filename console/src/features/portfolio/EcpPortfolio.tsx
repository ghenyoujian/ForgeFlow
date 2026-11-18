import { ArrowRight, CircleAlert, FileCheck2, Route, ShieldCheck } from "lucide-react";
import { Link } from "react-router-dom";
import { PortfolioPage } from "./index";

/**
 * ECP portfolio entry point.
 *
 * The existing PortfolioPage owns the authoritative `/portfolio` read and its
 * pagination/source stamp.  This shell deliberately adds no second data
 * authority or synthetic progress; it makes the three ECP review paths
 * explicit and lets the existing project rows remain the single drill-down
 * surface.
 */
export function EcpPortfolio() {
  return (
    <>
      <section className="ecp-portfolio-context" aria-label="ECP 项目组合审阅入口">
        <div className="ecp-portfolio-context-heading">
          <div>
            <span className="overview-eyebrow"><Route size={14} /> ECP 协作审阅</span>
            <h2>从项目组合进入需求、执行与证据</h2>
            <p>下方数据仍来自控制服务的分页组合查询。完成任务数、需求映射和 Gate 资格分别计量；缺失分母继续显示为未知。</p>
          </div>
          <div className="ecp-portfolio-context-actions">
            <Link className="button" to="/workspaces"><ShieldCheck size={15} />成员与授权</Link>
            <Link className="button" to="/recovery"><CircleAlert size={15} />恢复与维护</Link>
          </div>
        </div>
        <nav className="ecp-portfolio-review-links" aria-label="项目组合审阅路径">
          <Link to="/portfolio"><strong>项目组合</strong><span>服务端聚合、阻塞和观察来源</span><ArrowRight size={14} /></Link>
          <Link to="/projects/new"><strong>接入项目</strong><span>创建真实项目身份与范围</span><ArrowRight size={14} /></Link>
          <Link to="/checks"><strong>独立检查</strong><span>从项目继续下钻到验证与回执</span><FileCheck2 size={14} /></Link>
        </nav>
      </section>
      <PortfolioPage />
    </>
  );
}
